package services

const (
	SettingAutoSyncEnabled                = "auto_sync_enabled"
	SettingAutoSyncIntervalMinutes        = "auto_sync_interval_minutes"
	SettingAutoSyncConcurrency            = "auto_sync_concurrency"
	SettingAutoSyncRequestIntervalSeconds = "auto_sync_request_interval_seconds"
	SettingAutoSyncLastRunAt              = "auto_sync_last_run_at"
	SettingAutoSyncLastSuccessAt          = "auto_sync_last_success_at"
	SettingAutoSyncLastError              = "auto_sync_last_error"

	SettingRequestLoggingEnabled = "request_logging_enabled"

	SettingLogRetentionDays    = "log_retention_days"
	SettingLogCleanupLastRunAt = "log_cleanup_last_run_at"
	SettingLogCleanupLastError = "log_cleanup_last_error"

	SettingCacheEnabled    = "cache_enabled"
	SettingCacheTTLSeconds = "cache_ttl_seconds"
)
