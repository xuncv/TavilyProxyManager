package db

import (
	"os"
	"path/filepath"

	"tavily-proxy/server/internal/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func Open(path string) (*gorm.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}

	database, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	if err := database.AutoMigrate(&models.APIKey{}, &models.RequestLog{}, &models.RequestStat{}, &models.Setting{}, &models.SearchCache{}); err != nil {
		return nil, err
	}
	return database, nil
}
