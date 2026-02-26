package services

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"tavily-proxy/server/internal/models"

	"gorm.io/gorm"
)

type CacheService struct {
	db     *gorm.DB
	logger *slog.Logger
}

type CacheStats struct {
	Enabled        bool  `json:"enabled"`
	EntryCount     int64 `json:"entry_count"`
	TotalHits      int64 `json:"total_hits"`
	TotalSizeBytes int64 `json:"total_size_bytes"`
}

func NewCacheService(db *gorm.DB, logger *slog.Logger) *CacheService {
	return &CacheService{db: db, logger: logger}
}

func (s *CacheService) Lookup(ctx context.Context, cacheKey string) (*models.SearchCache, bool, error) {
	var entry models.SearchCache
	err := s.db.WithContext(ctx).
		Where("cache_key = ? AND expires_at > ?", cacheKey, time.Now()).
		First(&entry).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, false, nil
		}
		return nil, false, err
	}
	s.db.WithContext(ctx).Model(&entry).UpdateColumn("hit_count", gorm.Expr("hit_count + 1"))
	entry.HitCount++
	return &entry, true, nil
}

func (s *CacheService) Store(ctx context.Context, cacheKey, query, requestBody, responseBody string, statusCode int, ttl time.Duration) error {
	now := time.Now()
	expiresAt := now.Add(ttl)

	var existing models.SearchCache
	err := s.db.WithContext(ctx).Where("cache_key = ?", cacheKey).First(&existing).Error
	if err == nil {
		return s.db.WithContext(ctx).Model(&existing).Updates(map[string]any{
			"query":         query,
			"request_body":  requestBody,
			"response_body": responseBody,
			"status_code":   statusCode,
			"expires_at":    expiresAt,
			"hit_count":     0,
		}).Error
	}
	if err != gorm.ErrRecordNotFound {
		return err
	}

	entry := models.SearchCache{
		CacheKey:     cacheKey,
		Query:        query,
		RequestBody:  requestBody,
		ResponseBody: responseBody,
		StatusCode:   statusCode,
		HitCount:     0,
		ExpiresAt:    expiresAt,
		CreatedAt:    now,
	}
	return s.db.WithContext(ctx).Create(&entry).Error
}

func (s *CacheService) Stats(ctx context.Context) (CacheStats, error) {
	var stats CacheStats

	var entryCount int64
	if err := s.db.WithContext(ctx).Model(&models.SearchCache{}).
		Where("expires_at > ?", time.Now()).
		Count(&entryCount).Error; err != nil {
		return stats, err
	}
	stats.EntryCount = entryCount

	var totalHits *int64
	if err := s.db.WithContext(ctx).Model(&models.SearchCache{}).
		Select("COALESCE(SUM(hit_count), 0)").
		Scan(&totalHits).Error; err != nil {
		return stats, err
	}
	if totalHits != nil {
		stats.TotalHits = *totalHits
	}

	var totalSize *int64
	if err := s.db.WithContext(ctx).Model(&models.SearchCache{}).
		Where("expires_at > ?", time.Now()).
		Select("COALESCE(SUM(LENGTH(request_body) + LENGTH(response_body)), 0)").
		Scan(&totalSize).Error; err != nil {
		return stats, err
	}
	if totalSize != nil {
		stats.TotalSizeBytes = *totalSize
	}

	return stats, nil
}

func (s *CacheService) ClearAll(ctx context.Context) (int64, error) {
	result := s.db.WithContext(ctx).Where("1 = 1").Delete(&models.SearchCache{})
	return result.RowsAffected, result.Error
}

func (s *CacheService) CleanExpired(ctx context.Context) (int64, error) {
	result := s.db.WithContext(ctx).Where("expires_at <= ?", time.Now()).Delete(&models.SearchCache{})
	return result.RowsAffected, result.Error
}

func (s *CacheService) BuildCacheKey(body []byte) (string, string) {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return fmt.Sprintf("%x", sha256.Sum256(body)), ""
	}

	query, _ := m["query"].(string)

	keyFields := map[string]any{}
	for _, field := range []string{"query", "search_depth", "include_domains", "exclude_domains", "topic", "max_results"} {
		if v, ok := m[field]; ok {
			keyFields[field] = v
		}
	}

	keys := make([]string, 0, len(keyFields))
	for k := range keyFields {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for _, k := range keys {
		v, _ := json.Marshal(keyFields[k])
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.Write(v)
		sb.WriteByte('&')
	}

	hash := sha256.Sum256([]byte(sb.String()))
	return fmt.Sprintf("%x", hash), query
}
