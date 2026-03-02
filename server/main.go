package main

import (
	"context"
	"embed"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"tavily-proxy/server/internal/config"
	"tavily-proxy/server/internal/db"
	"tavily-proxy/server/internal/httpserver"
	"tavily-proxy/server/internal/jobs"
	"tavily-proxy/server/internal/logger"
	"tavily-proxy/server/internal/services"
)

//go:embed public
var embeddedPublic embed.FS

func main() {
	cfg := config.FromEnv()

	// Parse log level
	var level slog.Level
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	// Build writer (stdout + optional file)
	var w io.Writer = os.Stdout
	var fileWriter *logger.DailyRotateWriter
	if cfg.LogDir != "" {
		fileWriter = logger.NewDailyRotateWriter(cfg.LogDir, "proxy")
		w = io.MultiWriter(os.Stdout, fileWriter)
	}

	slogLogger := slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))

	database, err := db.Open(cfg.DatabasePath)
	if err != nil {
		slogLogger.Error("db open failed", "err", err)
		os.Exit(1)
	}

	masterKeyService := services.NewMasterKeyService(database, slogLogger)
	if err := masterKeyService.LoadOrCreate(context.Background()); err != nil {
		slogLogger.Error("master key init failed", "err", err)
		os.Exit(1)
	}

	settingsService := services.NewSettingsService(database)
	keyService := services.NewKeyService(database, slogLogger)
	logService := services.NewLogService(database, slogLogger)
	statsService := services.NewStatsService(database)

	if err := statsService.BackfillFromLogsIfEmpty(context.Background()); err != nil {
		slogLogger.Error("stats backfill failed", "err", err)
	}

	tavilyProxy := services.NewTavilyProxy(cfg.TavilyBaseURL, cfg.UpstreamTimeout, keyService, logService, statsService, slogLogger).
		WithSettings(settingsService)
	cacheService := services.NewCacheService(database, slogLogger)
	tavilyProxy.WithCache(cacheService)
	quotaSyncService := services.NewQuotaSyncService(keyService, tavilyProxy, slogLogger)
	quotaSyncJob := services.NewQuotaSyncJobService(keyService, quotaSyncService, slogLogger)

	srv := httpserver.New(httpserver.Dependencies{
		Config:           cfg,
		EmbeddedPublic:   embeddedPublic,
		MasterKeyService: masterKeyService,
		SettingsService:  settingsService,
		KeyService:       keyService,
		QuotaSyncService: quotaSyncService,
		QuotaSyncJob:     quotaSyncJob,
		LogService:       logService,
		StatsService:     statsService,
		CacheService:     cacheService,
		TavilyProxy:      tavilyProxy,
		Logger:           slogLogger,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	jobs.StartMonthlyReset(ctx, keyService, slogLogger)
	jobs.StartAutoQuotaSync(ctx, settingsService, quotaSyncService, slogLogger)
	jobs.StartLogCleanup(ctx, settingsService, logService, slogLogger)
	jobs.StartCacheCleanup(ctx, cacheService, slogLogger)

	go func() {
		slogLogger.Info("server listening", "addr", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil {
			slogLogger.Error("http server stopped", "err", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	if fileWriter != nil {
		_ = fileWriter.Close()
	}
}
