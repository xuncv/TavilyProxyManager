package httpserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"tavily-proxy/server/internal/mcpserver"
	"tavily-proxy/server/internal/services"
	"tavily-proxy/server/internal/util"
)

func NewRouter(deps Dependencies) http.Handler {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	publicFS, _ := fs.Sub(deps.EmbeddedPublic, "public")

	mcpHandler := mcpserver.NewHandler(mcpserver.Dependencies{
		MasterKey:  deps.MasterKeyService,
		Proxy:      deps.TavilyProxy,
		Stateless:  deps.Config.MCPStateless,
		SessionTTL: deps.Config.MCPSessionTTL,
	})
	r.Any("/mcp", gin.WrapH(mcpHandler))

	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	api := r.Group("/api", masterAuthMiddleware(deps.MasterKeyService))
	{
		api.GET("/keys", func(c *gin.Context) { handleListKeys(c, deps.KeyService) })
		api.POST("/keys", func(c *gin.Context) { handleCreateKey(c, deps.KeyService) })
		api.GET("/keys/export", func(c *gin.Context) { handleExportKeys(c, deps.KeyService) })
		api.GET("/keys/:id/raw", func(c *gin.Context) { handleGetKeyRaw(c, deps.KeyService, c.Param("id")) })
		api.GET("/keys/sync", func(c *gin.Context) { handleGetSyncAllKeys(c, deps.QuotaSyncJob) })
		api.POST("/keys/sync", func(c *gin.Context) { handleStartSyncAllKeys(c, deps.QuotaSyncJob) })
		api.DELETE("/keys/invalid", func(c *gin.Context) { handleDeleteInvalidKeys(c, deps.KeyService) })
		api.PUT("/keys/:id", func(c *gin.Context) { handleUpdateKey(c, deps, c.Param("id")) })
		api.DELETE("/keys/:id", func(c *gin.Context) { handleDeleteKey(c, deps.KeyService, c.Param("id")) })

		api.GET("/logs/status-codes", func(c *gin.Context) { handleLogStatusCodes(c, deps.LogService) })
		api.GET("/logs", func(c *gin.Context) { handleListLogs(c, deps.LogService) })
		api.DELETE("/logs", func(c *gin.Context) { handleClearLogs(c, deps.LogService) })
		api.GET("/stats", func(c *gin.Context) { handleStats(c, deps.StatsService) })
		api.GET("/stats/timeseries", func(c *gin.Context) { handleTimeSeries(c, deps.StatsService) })

		api.GET("/settings/master-key", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"master_key": deps.MasterKeyService.Get()})
		})
		api.POST("/settings/master-key/reset", func(c *gin.Context) {
			newKey, err := deps.MasterKeyService.Reset(c.Request.Context())
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "reset_failed"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"master_key": newKey})
		})

		api.GET("/settings/auto-sync", func(c *gin.Context) { handleGetAutoSync(c, deps.SettingsService) })
		api.PUT("/settings/auto-sync", func(c *gin.Context) { handleSetAutoSync(c, deps.SettingsService) })
		api.GET("/settings/log-cleanup", func(c *gin.Context) { handleGetLogCleanup(c, deps.SettingsService) })
		api.PUT("/settings/log-cleanup", func(c *gin.Context) { handleSetLogCleanup(c, deps.SettingsService) })

		api.GET("/settings/cache", func(c *gin.Context) { handleGetCache(c, deps.SettingsService) })
		api.PUT("/settings/cache", func(c *gin.Context) { handleSetCache(c, deps.SettingsService) })
		api.DELETE("/cache", func(c *gin.Context) { handleClearCache(c, deps.CacheService) })
		api.GET("/cache/stats", func(c *gin.Context) { handleCacheStats(c, deps.SettingsService, deps.CacheService) })
	}

	r.NoRoute(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/api/") || c.Request.URL.Path == "/api" {
			c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
			return
		}

		if isStaticAssetRequest(c.Request) {
			serveEmbeddedFile(c, publicFS, cleanPublicPath(c.Request.URL.Path))
			return
		}

		body, _ := io.ReadAll(c.Request.Body)

		authHeaderToken := parseBearerToken(c.GetHeader("Authorization"))
		apiKeyFromQuery, sanitizedQuery := stripAPIKeyFromRawQuery(c.Request.URL.RawQuery)
		apiKeyFromBody, sanitizedBody := stripAPIKeyFromJSON(body)

		hasCredential := authHeaderToken != "" || apiKeyFromBody != "" || apiKeyFromQuery != ""
		if deps.MasterKeyService.Authenticate(authHeaderToken) || deps.MasterKeyService.Authenticate(apiKeyFromBody) || deps.MasterKeyService.Authenticate(apiKeyFromQuery) {
			handleProxy(c, deps.TavilyProxy, sanitizedBody, sanitizedQuery)
			return
		}
		if hasCredential {
			respondUnauthorized(c)
			return
		}

		if c.Request.Method != http.MethodGet {
			respondUnauthorized(c)
			return
		}
		if !acceptsHTML(c.Request) {
			respondUnauthorized(c)
			return
		}
		serveEmbeddedFile(c, publicFS, "index.html")
	})

	return r
}

func masterAuthMiddleware(master *services.MasterKeyService) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := parseBearerToken(c.GetHeader("Authorization"))
		if !master.Authenticate(token) {
			respondUnauthorized(c)
			c.Abort()
			return
		}
		c.Next()
	}
}

func respondUnauthorized(c *gin.Context) {
	c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
}

func parseBearerToken(authHeader string) string {
	if authHeader == "" {
		return ""
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 {
		return ""
	}
	if !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func acceptsHTML(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return accept == "" || strings.Contains(accept, "text/html")
}

func isStaticAssetRequest(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	p := r.URL.Path
	if p == "/" {
		return false
	}
	if strings.HasPrefix(p, "/assets/") {
		return true
	}
	if strings.Contains(path.Base(p), ".") {
		return true
	}
	return false
}

func cleanPublicPath(p string) string {
	p = strings.TrimPrefix(p, "/")
	p = path.Clean(p)
	p = strings.TrimPrefix(p, "../")
	return p
}

func serveEmbeddedFile(c *gin.Context, publicFS fs.FS, filePath string) {
	f, err := publicFS.Open(filePath)
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	defer f.Close()

	stat, err := f.Stat()
	if err == nil && stat.IsDir() {
		c.Status(http.StatusNotFound)
		return
	}

	data, err := io.ReadAll(f)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	c.Data(http.StatusOK, contentTypeByExt(filePath), data)
}

func contentTypeByExt(p string) string {
	switch strings.ToLower(path.Ext(p)) {
	case ".html":
		return "text/html; charset=utf-8"
	case ".js":
		return "application/javascript; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".svg":
		return "image/svg+xml"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".ico":
		return "image/x-icon"
	case ".json":
		return "application/json; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}

func handleListKeys(c *gin.Context, keys *services.KeyService) {
	items, err := keys.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}

	type keyDTO struct {
		ID         uint    `json:"id"`
		KeyMasked  string  `json:"key"`
		Alias      string  `json:"alias"`
		TotalQuota int     `json:"total_quota"`
		UsedQuota  int     `json:"used_quota"`
		IsActive   bool    `json:"is_active"`
		IsInvalid  bool    `json:"is_invalid"`
		LastUsedAt *string `json:"last_used_at"`
		CreatedAt  string  `json:"created_at"`
	}

	out := make([]keyDTO, 0, len(items))
	for _, k := range items {
		var lastUsed *string
		if k.LastUsedAt != nil {
			v := k.LastUsedAt.Format(time.RFC3339)
			lastUsed = &v
		}
		out = append(out, keyDTO{
			ID:         k.ID,
			KeyMasked:  util.MaskAPIKey(k.Key),
			Alias:      k.Alias,
			TotalQuota: k.TotalQuota,
			UsedQuota:  k.UsedQuota,
			IsActive:   k.IsActive,
			IsInvalid:  k.IsInvalid,
			LastUsedAt: lastUsed,
			CreatedAt:  k.CreatedAt.Format(time.RFC3339),
		})
	}
	c.JSON(http.StatusOK, gin.H{"items": out})
}

func handleExportKeys(c *gin.Context, keys *services.KeyService) {
	items, err := keys.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}

	var buf bytes.Buffer
	var exported int
	for _, k := range items {
		if k.IsInvalid {
			continue
		}
		key := strings.TrimSpace(k.Key)
		if key == "" {
			continue
		}
		buf.WriteString(key)
		buf.WriteByte('\n')
		exported++
	}

	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Header("Content-Disposition", `attachment; filename="tavily-keys.txt"`)
	c.Header("X-Exported-Count", strconv.Itoa(exported))
	c.Status(http.StatusOK)
	_, _ = io.Copy(c.Writer, &buf)
}

func handleCreateKey(c *gin.Context, keys *services.KeyService) {
	var body struct {
		Key        string `json:"key"`
		Alias      string `json:"alias"`
		TotalQuota int    `json:"total_quota"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_json"})
		return
	}
	if strings.TrimSpace(body.Key) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_key"})
		return
	}
	if strings.TrimSpace(body.Alias) == "" {
		body.Alias = "Default"
	}

	created, err := keys.Create(c.Request.Context(), strings.TrimSpace(body.Key), strings.TrimSpace(body.Alias), body.TotalQuota)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "create_failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"item": gin.H{
			"id":          created.ID,
			"key":         util.MaskAPIKey(created.Key),
			"alias":       created.Alias,
			"total_quota": created.TotalQuota,
			"used_quota":  created.UsedQuota,
			"is_active":   created.IsActive,
			"is_invalid":  created.IsInvalid,
			"created_at":  created.CreatedAt.Format(time.RFC3339),
		},
	})
}

func handleGetKeyRaw(c *gin.Context, keys *services.KeyService, idStr string) {
	id, err := parseUintParam(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_id"})
		return
	}

	key, err := keys.FindByID(c.Request.Context(), uint(id))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}
	if key == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"key": key.Key})
}

func handleUpdateKey(c *gin.Context, deps Dependencies, idStr string) {
	id, err := parseUintParam(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_id"})
		return
	}

	var body services.KeyUpdate
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_json"})
		return
	}

	updated, err := deps.KeyService.Update(c.Request.Context(), uint(id), body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "update_failed"})
		return
	}

	if body.SyncUsage {
		if _, err := deps.QuotaSyncService.SyncOne(c.Request.Context(), uint(id)); err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
			return
		}
		if refreshed, err := deps.KeyService.Get(c.Request.Context(), uint(id)); err == nil && refreshed != nil {
			updated = refreshed
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"item": gin.H{
			"id":          updated.ID,
			"key":         util.MaskAPIKey(updated.Key),
			"alias":       updated.Alias,
			"total_quota": updated.TotalQuota,
			"used_quota":  updated.UsedQuota,
			"is_active":   updated.IsActive,
			"is_invalid":  updated.IsInvalid,
		},
	})
}

func handleDeleteInvalidKeys(c *gin.Context, keys *services.KeyService) {
	deleted, err := keys.DeleteInvalid(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete_failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": deleted})
}

func handleGetSyncAllKeys(c *gin.Context, jobs *services.QuotaSyncJobService) {
	c.JSON(http.StatusOK, jobs.Get())
}

func handleStartSyncAllKeys(c *gin.Context, jobs *services.QuotaSyncJobService) {
	var body struct {
		IntervalMs *int `json:"interval_ms"`
	}
	if err := c.ShouldBindJSON(&body); err != nil && !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_json"})
		return
	}

	interval := time.Duration(0)
	if body.IntervalMs != nil {
		interval = time.Duration(*body.IntervalMs) * time.Millisecond
	}

	result, _, err := jobs.Start(interval)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "sync_failed"})
		return
	}
	c.JSON(http.StatusOK, result)
}

func handleGetAutoSync(c *gin.Context, settings *services.SettingsService) {
	enabled, err := settings.GetBool(c.Request.Context(), services.SettingAutoSyncEnabled, false)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}
	interval, err := settings.GetInt(c.Request.Context(), services.SettingAutoSyncIntervalMinutes, 60)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}
	if interval < 1 {
		interval = 1
	}

	concurrency := 1

	requestIntervalSeconds, err := settings.GetInt(c.Request.Context(), services.SettingAutoSyncRequestIntervalSeconds, 0)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}
	if requestIntervalSeconds < 0 {
		requestIntervalSeconds = 0
	}
	if requestIntervalSeconds > 60 {
		requestIntervalSeconds = 60
	}

	lastRun, _ := settings.GetTime(c.Request.Context(), services.SettingAutoSyncLastRunAt)
	lastSuccess, _ := settings.GetTime(c.Request.Context(), services.SettingAutoSyncLastSuccessAt)
	lastErr, _, _ := settings.Get(c.Request.Context(), services.SettingAutoSyncLastError)

	var lastRunStr *string
	if lastRun != nil {
		v := lastRun.Format(time.RFC3339)
		lastRunStr = &v
	}
	var lastSuccessStr *string
	if lastSuccess != nil {
		v := lastSuccess.Format(time.RFC3339)
		lastSuccessStr = &v
	}

	c.JSON(http.StatusOK, gin.H{
		"enabled":                  enabled,
		"interval_minutes":         interval,
		"concurrency":              concurrency,
		"request_interval_seconds": requestIntervalSeconds,
		"last_run_at":              lastRunStr,
		"last_success_at":          lastSuccessStr,
		"last_error":               lastErr,
	})
}

func handleSetAutoSync(c *gin.Context, settings *services.SettingsService) {
	var body struct {
		Enabled                *bool `json:"enabled"`
		IntervalMinutes        *int  `json:"interval_minutes"`
		RequestIntervalSeconds *int  `json:"request_interval_seconds"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_json"})
		return
	}

	if body.Enabled == nil && body.IntervalMinutes == nil && body.RequestIntervalSeconds == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_fields"})
		return
	}

	if body.IntervalMinutes != nil {
		if *body.IntervalMinutes < 1 || *body.IntervalMinutes > 1440 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_interval_minutes"})
			return
		}
		if err := settings.SetInt(c.Request.Context(), services.SettingAutoSyncIntervalMinutes, *body.IntervalMinutes); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
			return
		}
	}
	if body.RequestIntervalSeconds != nil {
		if *body.RequestIntervalSeconds < 0 || *body.RequestIntervalSeconds > 60 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request_interval_seconds"})
			return
		}
		if err := settings.SetInt(c.Request.Context(), services.SettingAutoSyncRequestIntervalSeconds, *body.RequestIntervalSeconds); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
			return
		}
	}
	if body.Enabled != nil {
		if err := settings.SetBool(c.Request.Context(), services.SettingAutoSyncEnabled, *body.Enabled); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
			return
		}
	}

	c.Status(http.StatusNoContent)
}

func handleGetLogCleanup(c *gin.Context, settings *services.SettingsService) {
	retentionDays, err := settings.GetInt(c.Request.Context(), services.SettingLogRetentionDays, 30)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}
	if retentionDays < 0 {
		retentionDays = 0
	}

	loggingEnabled, err := settings.GetBool(c.Request.Context(), services.SettingRequestLoggingEnabled, true)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}

	lastRun, _ := settings.GetTime(c.Request.Context(), services.SettingLogCleanupLastRunAt)
	lastErr, _, _ := settings.Get(c.Request.Context(), services.SettingLogCleanupLastError)

	var lastRunStr *string
	if lastRun != nil {
		v := lastRun.Format(time.RFC3339)
		lastRunStr = &v
	}

	c.JSON(http.StatusOK, gin.H{
		"logging_enabled": loggingEnabled,
		"retention_days":  retentionDays,
		"last_run_at":     lastRunStr,
		"last_error":      lastErr,
	})
}

func handleSetLogCleanup(c *gin.Context, settings *services.SettingsService) {
	var body struct {
		LoggingEnabled *bool `json:"logging_enabled"`
		RetentionDays  *int  `json:"retention_days"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_json"})
		return
	}
	if body.RetentionDays == nil && body.LoggingEnabled == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_fields"})
		return
	}

	if body.LoggingEnabled != nil {
		if err := settings.SetBool(c.Request.Context(), services.SettingRequestLoggingEnabled, *body.LoggingEnabled); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
			return
		}
	}

	if body.RetentionDays != nil {
		if *body.RetentionDays < 0 || *body.RetentionDays > 3650 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_retention_days"})
			return
		}
		if err := settings.SetInt(c.Request.Context(), services.SettingLogRetentionDays, *body.RetentionDays); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
			return
		}
	}
	c.Status(http.StatusNoContent)
}

func handleDeleteKey(c *gin.Context, keys *services.KeyService, idStr string) {
	id, err := parseUintParam(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_id"})
		return
	}
	if err := keys.Delete(c.Request.Context(), uint(id)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete_failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func handleListLogs(c *gin.Context, logs *services.LogService) {
	page, _ := strconv.Atoi(c.Query("page"))
	size, _ := strconv.Atoi(c.Query("page_size"))

	var statusCode *int
	if v := c.Query("status_code"); v != "" {
		parsed, err := strconv.Atoi(v)
		if err != nil || parsed < 0 || parsed > 999 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_status_code"})
			return
		}
		statusCode = &parsed
	}

	out, err := logs.List(c.Request.Context(), page, size, statusCode)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}
	c.JSON(http.StatusOK, out)
}

func handleClearLogs(c *gin.Context, logs *services.LogService) {
	deleted, err := logs.DeleteAll(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": deleted})
}

func handleLogStatusCodes(c *gin.Context, logs *services.LogService) {
	out, err := logs.StatusCodeCounts(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}
	c.JSON(http.StatusOK, out)
}

func handleStats(c *gin.Context, stats *services.StatsService) {
	out, err := stats.Get(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}
	c.JSON(http.StatusOK, out)
}

func handleTimeSeries(c *gin.Context, stats *services.StatsService) {
	granularity := c.Query("granularity")
	out, err := stats.TimeSeries(c.Request.Context(), granularity)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_granularity"})
		return
	}
	c.JSON(http.StatusOK, out)
}

func handleProxy(c *gin.Context, proxy *services.TavilyProxy, body []byte, rawQuery string) {
	resp, err := proxy.Do(c.Request.Context(), services.ProxyRequest{
		Method:      c.Request.Method,
		Path:        c.Request.URL.Path,
		RawQuery:    rawQuery,
		Headers:     c.Request.Header.Clone(),
		Body:        body,
		ClientIP:    c.ClientIP(),
		ContentType: c.GetHeader("Content-Type"),
	})
	if err != nil {
		if errors.Is(err, services.ErrNoAvailableKeys) {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error":   "no_available_keys",
				"message": "No active Tavily API keys with remaining quota.",
			})
			return
		}
		c.JSON(http.StatusBadGateway, gin.H{"error": "upstream_error"})
		return
	}

	for k, vv := range resp.Headers {
		if isHopByHopHeader(k) || strings.EqualFold(k, "Content-Length") {
			continue
		}
		for _, v := range vv {
			c.Writer.Header().Add(k, v)
		}
	}
	c.Header("X-Proxy-Request-ID", resp.ProxyRequestID)
	if resp.TavilyRequestID != "" {
		c.Header("X-Tavily-Request-ID", resp.TavilyRequestID)
	}

	c.Status(resp.StatusCode)
	_, _ = io.Copy(c.Writer, bytes.NewReader(resp.Body))
}

func isHopByHopHeader(k string) bool {
	switch strings.ToLower(k) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

func stripAPIKeyFromJSON(body []byte) (apiKey string, sanitized []byte) {
	if len(body) == 0 {
		return "", body
	}

	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return "", body
	}

	var m map[string]any
	if err := json.Unmarshal(trimmed, &m); err != nil {
		return "", body
	}

	changed := false
	if v, ok := m["api_key"]; ok {
		if s, ok := v.(string); ok {
			apiKey = strings.TrimSpace(s)
		}
		delete(m, "api_key")
		changed = true
	}
	if v, ok := m["apiKey"]; ok {
		if apiKey == "" {
			if s, ok := v.(string); ok {
				apiKey = strings.TrimSpace(s)
			}
		}
		delete(m, "apiKey")
		changed = true
	}

	if !changed {
		return "", body
	}

	out, err := json.Marshal(m)
	if err != nil {
		return apiKey, body
	}
	return apiKey, out
}

func stripAPIKeyFromRawQuery(rawQuery string) (apiKey string, sanitized string) {
	if rawQuery == "" {
		return "", rawQuery
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "", rawQuery
	}

	apiKey = strings.TrimSpace(values.Get("api_key"))
	if apiKey == "" {
		apiKey = strings.TrimSpace(values.Get("apiKey"))
	}
	values.Del("api_key")
	values.Del("apiKey")

	return apiKey, values.Encode()
}

func handleGetCache(c *gin.Context, settings *services.SettingsService) {
	enabled, err := settings.GetBool(c.Request.Context(), services.SettingCacheEnabled, false)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}
	ttl, err := settings.GetInt(c.Request.Context(), services.SettingCacheTTLSeconds, 43200)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"enabled":     enabled,
		"ttl_seconds": ttl,
	})
}

func handleSetCache(c *gin.Context, settings *services.SettingsService) {
	var body struct {
		Enabled    *bool `json:"enabled"`
		TTLSeconds *int  `json:"ttl_seconds"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_json"})
		return
	}
	if body.Enabled == nil && body.TTLSeconds == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing_fields"})
		return
	}
	if body.TTLSeconds != nil {
		if *body.TTLSeconds < 60 || *body.TTLSeconds > 604800 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_ttl_seconds"})
			return
		}
		if err := settings.SetInt(c.Request.Context(), services.SettingCacheTTLSeconds, *body.TTLSeconds); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
			return
		}
	}
	if body.Enabled != nil {
		if err := settings.SetBool(c.Request.Context(), services.SettingCacheEnabled, *body.Enabled); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
			return
		}
	}
	c.Status(http.StatusNoContent)
}

func handleClearCache(c *gin.Context, cache *services.CacheService) {
	deleted, err := cache.ClearAll(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": deleted})
}

func handleCacheStats(c *gin.Context, settings *services.SettingsService, cache *services.CacheService) {
	stats, err := cache.Stats(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}
	enabled, _ := settings.GetBool(c.Request.Context(), services.SettingCacheEnabled, false)
	stats.Enabled = enabled
	c.JSON(http.StatusOK, stats)
}

func parseUintParam(v string) (uint64, error) {
	return strconv.ParseUint(v, 10, 64)
}
