package services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"tavily-proxy/server/internal/models"
)

type TavilyProxy struct {
	baseURL string
	client  *http.Client

	settings *SettingsService
	cache    *CacheService
	keys     *KeyService
	logs     *LogService
	stats    *StatsService
	logger   *slog.Logger
}

type ProxyRequest struct {
	Method      string
	Path        string
	RawQuery    string
	Headers     http.Header
	Body        []byte
	ClientIP    string
	ContentType string
}

type ProxyResponse struct {
	StatusCode      int
	Headers         http.Header
	Body            []byte
	ProxyRequestID  string
	TavilyRequestID string
}

func NewTavilyProxy(baseURL string, timeout time.Duration, keys *KeyService, logs *LogService, stats *StatsService, logger *slog.Logger) *TavilyProxy {
	return &TavilyProxy{
		baseURL: strings.TrimRight(baseURL, "/"),
		client: &http.Client{
			Timeout: timeout,
		},
		keys:     keys,
		logs:     logs,
		stats:    stats,
		logger:   logger,
		settings: nil,
	}
}

var ErrNoAvailableKeys = errors.New("no available keys")

func (p *TavilyProxy) WithSettings(settings *SettingsService) *TavilyProxy {
	p.settings = settings
	return p
}

func (p *TavilyProxy) WithCache(cache *CacheService) *TavilyProxy {
	p.cache = cache
	return p
}

func (p *TavilyProxy) isRequestLoggingEnabled(ctx context.Context) bool {
	if p.settings == nil {
		return true
	}
	enabled, err := p.settings.GetBool(ctx, SettingRequestLoggingEnabled, true)
	if err != nil {
		return true
	}
	return enabled
}

func (p *TavilyProxy) Do(ctx context.Context, req ProxyRequest) (ProxyResponse, error) {
	const maxLogBytes = 32 * 1024

	proxyReqID := uuid.NewString()

	loggingEnabled := p.logs != nil && p.isRequestLoggingEnabled(ctx)
	captureBodies := strings.EqualFold(req.Method, http.MethodPost) && req.Path == "/search"
	requestBody, requestTruncated := "", false
	if loggingEnabled && captureBodies && len(req.Body) > 0 {
		requestBody, requestTruncated = truncateForLog(req.Body, maxLogBytes)
	}

	// Cache lookup for POST /search
	noCache := false
	if captureBodies && req.RawQuery != "" {
		if vals, err := url.ParseQuery(req.RawQuery); err == nil {
			noCache = strings.EqualFold(vals.Get("no_cache"), "true")
			vals.Del("no_cache")
			req.RawQuery = vals.Encode()
		}
	}

	if captureBodies && !noCache && p.cache != nil && p.isCacheEnabled(ctx) {
		cacheKey, query := p.cache.BuildCacheKey(req.Body)
		if entry, hit, err := p.cache.Lookup(ctx, cacheKey); err == nil && hit {
			createdAt := time.Now()
			if loggingEnabled {
				responseBody, responseTruncated := truncateForLog([]byte(entry.ResponseBody), maxLogBytes)
				_ = p.logs.Create(ctx, &models.RequestLog{
					RequestID:         proxyReqID,
					KeyUsed:           0,
					KeyAlias:          "",
					Endpoint:          req.Path,
					StatusCode:        entry.StatusCode,
					LatencyMs:         0,
					RequestBody:       requestBody,
					RequestTruncated:  requestTruncated,
					ResponseBody:      responseBody,
					ResponseTruncated: responseTruncated,
					CacheHit:          true,
					ClientIP:          req.ClientIP,
					CreatedAt:         createdAt,
				})
			}
			if p.stats != nil {
				_ = p.stats.RecordRequest(ctx, req.Path, createdAt)
			}
			p.logger.Info("cache hit", "query", query, "cache_key", cacheKey[:12])
			return ProxyResponse{
				StatusCode:     entry.StatusCode,
				Headers:        http.Header{"Content-Type": {"application/json"}},
				Body:           []byte(entry.ResponseBody),
				ProxyRequestID: proxyReqID,
			}, nil
		}
	}

	candidates, err := p.keys.Candidates(ctx)
	if err != nil {
		return ProxyResponse{}, err
	}

	if len(candidates) == 0 {
		if captureBodies {
			createdAt := time.Now()
			if loggingEnabled {
				_ = p.logs.Create(ctx, &models.RequestLog{
					RequestID:         proxyReqID,
					KeyUsed:           0,
					KeyAlias:          "",
					Endpoint:          req.Path,
					StatusCode:        http.StatusServiceUnavailable,
					LatencyMs:         0,
					RequestBody:       requestBody,
					RequestTruncated:  requestTruncated,
					ResponseBody:      `{"error":"no_available_keys","message":"No active Tavily API keys with remaining quota."}`,
					ResponseTruncated: false,
					ClientIP:          req.ClientIP,
					CreatedAt:         createdAt,
				})
			}
			if p.stats != nil {
				_ = p.stats.RecordRequest(ctx, req.Path, createdAt)
			}
		}
		return ProxyResponse{}, ErrNoAvailableKeys
	}

	var lastErr error
	for _, key := range candidates {
		resp, status, latencyMs, tavilyReqID, err := p.tryKey(ctx, key.ID, key.Key, req, proxyReqID)

		if err != nil {
			lastErr = err
			continue
		}

		switch status {
		case http.StatusUnauthorized:
			_ = p.keys.MarkInvalid(ctx, key.ID)
			continue
		case http.StatusTooManyRequests, 432, 433:
			_ = p.keys.MarkExhausted(ctx, key.ID)
			continue
		}

		if status == http.StatusOK && !strings.EqualFold(req.Method, http.MethodGet) {
			_ = p.keys.IncrementUsed(ctx, key.ID)
		}

		createdAt := time.Now()
		if loggingEnabled {
			if captureBodies {
				responseBody, responseTruncated := truncateForLog(resp.Body, maxLogBytes)
				_ = p.logs.Create(ctx, &models.RequestLog{
					RequestID:         proxyReqID,
					KeyUsed:           key.ID,
					KeyAlias:          key.Alias,
					Endpoint:          req.Path,
					StatusCode:        status,
					LatencyMs:         latencyMs,
					RequestBody:       requestBody,
					RequestTruncated:  requestTruncated,
					ResponseBody:      responseBody,
					ResponseTruncated: responseTruncated,
					ClientIP:          req.ClientIP,
					CreatedAt:         createdAt,
				})
			} else {
				_ = p.logs.Create(ctx, &models.RequestLog{
					RequestID:  proxyReqID,
					KeyUsed:    key.ID,
					KeyAlias:   key.Alias,
					Endpoint:   req.Path,
					StatusCode: status,
					LatencyMs:  latencyMs,
					ClientIP:   req.ClientIP,
					CreatedAt:  createdAt,
				})
			}
		}
		if p.stats != nil {
			_ = p.stats.RecordRequest(ctx, req.Path, createdAt)
		}

		// Store in cache after successful upstream response
		if captureBodies && status == http.StatusOK && p.cache != nil && p.isCacheEnabled(ctx) {
			cacheKey, query := p.cache.BuildCacheKey(req.Body)
			ttl := p.getCacheTTL(ctx)
			if err := p.cache.Store(ctx, cacheKey, query, string(req.Body), string(resp.Body), status, ttl); err != nil {
				p.logger.Warn("cache store failed", "err", err)
			}
		}

		resp.ProxyRequestID = proxyReqID
		resp.TavilyRequestID = tavilyReqID
		return resp, nil
	}

	if captureBodies && lastErr != nil {
		createdAt := time.Now()
		if loggingEnabled {
			_ = p.logs.Create(ctx, &models.RequestLog{
				RequestID:         proxyReqID,
				KeyUsed:           0,
				KeyAlias:          "",
				Endpoint:          req.Path,
				StatusCode:        http.StatusBadGateway,
				LatencyMs:         0,
				RequestBody:       requestBody,
				RequestTruncated:  requestTruncated,
				ResponseBody:      lastErr.Error(),
				ResponseTruncated: false,
				ClientIP:          req.ClientIP,
				CreatedAt:         createdAt,
			})
		}
		if p.stats != nil {
			_ = p.stats.RecordRequest(ctx, req.Path, createdAt)
		}
	}

	return ProxyResponse{}, ErrNoAvailableKeys
}

func truncateForLog(data []byte, maxBytes int) (string, bool) {
	if maxBytes <= 0 || len(data) <= maxBytes {
		return string(data), false
	}
	return string(data[:maxBytes]), true
}

func (p *TavilyProxy) tryKey(ctx context.Context, keyID uint, tavilyKey string, req ProxyRequest, proxyReqID string) (ProxyResponse, int, int64, string, error) {
	url := p.baseURL + req.Path
	if req.RawQuery != "" {
		url += "?" + req.RawQuery
	}

	upstreamReq, err := http.NewRequestWithContext(ctx, req.Method, url, bytes.NewReader(req.Body))
	if err != nil {
		return ProxyResponse{}, 0, 0, "", err
	}

	copyHeaders(upstreamReq.Header, req.Headers)
	upstreamReq.Header.Del("Authorization")
	upstreamReq.Header.Set("Authorization", "Bearer "+tavilyKey)
	if req.ContentType != "" && upstreamReq.Header.Get("Content-Type") == "" {
		upstreamReq.Header.Set("Content-Type", req.ContentType)
	}
	upstreamReq.Header.Set("X-Proxy-Request-Id", proxyReqID)

	start := time.Now()
	upstreamResp, err := p.client.Do(upstreamReq)
	latencyMs := time.Since(start).Milliseconds()
	if err != nil {
		return ProxyResponse{}, 0, latencyMs, "", err
	}
	defer upstreamResp.Body.Close()

	body, err := io.ReadAll(upstreamResp.Body)
	if err != nil {
		return ProxyResponse{}, upstreamResp.StatusCode, latencyMs, "", err
	}

	requestID := extractRequestID(body)

	return ProxyResponse{
		StatusCode:     upstreamResp.StatusCode,
		Headers:        upstreamResp.Header.Clone(),
		Body:           body,
		ProxyRequestID: proxyReqID,
	}, upstreamResp.StatusCode, latencyMs, requestID, nil
}

func copyHeaders(dst http.Header, src http.Header) {
	for k, vv := range src {
		switch strings.ToLower(k) {
		case "host", "content-length":
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func extractRequestID(body []byte) string {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return ""
	}
	if v, ok := m["request_id"].(string); ok && v != "" {
		return v
	}
	if v, ok := m["requestId"].(string); ok && v != "" {
		return v
	}
	return ""
}

type usageResponse struct {
	Key struct {
		Usage int  `json:"usage"`
		Limit *int `json:"limit"`
	} `json:"key"`
}

type UpstreamStatusError struct {
	StatusCode int
	Body       string
}

func (e *UpstreamStatusError) Error() string {
	body := strings.TrimSpace(e.Body)
	if body == "" {
		return fmt.Sprintf("upstream status %d", e.StatusCode)
	}
	return fmt.Sprintf("upstream status %d: %s", e.StatusCode, body)
}

func (p *TavilyProxy) isCacheEnabled(ctx context.Context) bool {
	if p.settings == nil {
		return false
	}
	enabled, err := p.settings.GetBool(ctx, SettingCacheEnabled, false)
	if err != nil {
		return false
	}
	return enabled
}

func (p *TavilyProxy) getCacheTTL(ctx context.Context) time.Duration {
	if p.settings == nil {
		return 43200 * time.Second
	}
	seconds, err := p.settings.GetInt(ctx, SettingCacheTTLSeconds, 43200)
	if err != nil || seconds < 60 {
		return 43200 * time.Second
	}
	return time.Duration(seconds) * time.Second
}

func (p *TavilyProxy) GetUsage(ctx context.Context, tavilyKey string) (int, *int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.baseURL+"/usage", nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tavilyKey)

	resp, err := p.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return 0, nil, &UpstreamStatusError{StatusCode: resp.StatusCode, Body: string(body)}
	}

	var out usageResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return 0, nil, err
	}
	return out.Key.Usage, out.Key.Limit, nil
}
