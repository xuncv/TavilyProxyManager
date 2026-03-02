package services

import (
	"context"
	"strconv"
	"strings"
	"time"

	"tavily-proxy/server/internal/models"

	"gorm.io/gorm"
)

type SettingsService struct {
	db *gorm.DB
}

func NewSettingsService(db *gorm.DB) *SettingsService {
	return &SettingsService{db: db}
}

func (s *SettingsService) Get(ctx context.Context, key string) (string, bool, error) {
	var setting models.Setting
	tx := s.db.WithContext(ctx).Where("key = ?", key).Limit(1).Find(&setting)
	if tx.Error != nil {
		return "", false, tx.Error
	}
	if tx.RowsAffected == 0 {
		return "", false, nil
	}
	return setting.Value, true, nil
}

func (s *SettingsService) Set(ctx context.Context, key, value string) error {
	return s.db.WithContext(ctx).Save(&models.Setting{Key: key, Value: value}).Error
}

func (s *SettingsService) GetBool(ctx context.Context, key string, def bool) (bool, error) {
	v, ok, err := s.Get(ctx, key)
	if err != nil || !ok {
		return def, err
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "y", "on":
		return true, nil
	case "0", "false", "no", "n", "off":
		return false, nil
	default:
		return def, nil
	}
}

func (s *SettingsService) SetBool(ctx context.Context, key string, value bool) error {
	if value {
		return s.Set(ctx, key, "true")
	}
	return s.Set(ctx, key, "false")
}

func (s *SettingsService) GetInt(ctx context.Context, key string, def int) (int, error) {
	v, ok, err := s.Get(ctx, key)
	if err != nil || !ok {
		return def, err
	}
	i, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return def, nil
	}
	return i, nil
}

func (s *SettingsService) SetInt(ctx context.Context, key string, value int) error {
	return s.Set(ctx, key, strconv.Itoa(value))
}

func (s *SettingsService) GetTime(ctx context.Context, key string) (*time.Time, error) {
	v, ok, err := s.Get(ctx, key)
	if err != nil || !ok {
		return nil, err
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(v))
	if err != nil {
		return nil, nil
	}
	return &t, nil
}

func (s *SettingsService) SetTime(ctx context.Context, key string, value time.Time) error {
	return s.Set(ctx, key, value.UTC().Format(time.RFC3339))
}
