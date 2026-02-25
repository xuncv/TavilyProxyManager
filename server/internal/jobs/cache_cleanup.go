package jobs

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"tavily-proxy/server/internal/services"
)

func StartCacheCleanup(ctx context.Context, cache *services.CacheService, logger *slog.Logger) {
	var running atomic.Bool

	go func() {
		ticker := time.NewTicker(30 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !running.CompareAndSwap(false, true) {
					continue
				}

				go func() {
					defer running.Store(false)

					runCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
					defer cancel()

					deleted, err := cache.CleanExpired(runCtx)
					if err != nil {
						logger.Error("cache-cleanup: delete failed", "err", err)
						return
					}
					if deleted > 0 {
						logger.Info("cache-cleanup: completed", "deleted", deleted)
					}
				}()
			}
		}
	}()
}
