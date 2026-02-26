package models

import "time"

type APIKey struct {
	ID         uint       `gorm:"primaryKey" json:"id"`
	Key        string     `gorm:"uniqueIndex;not null" json:"-"`
	Alias      string     `gorm:"not null" json:"alias"`
	TotalQuota int        `gorm:"not null;default:1000" json:"total_quota"`
	UsedQuota  int        `gorm:"not null;default:0" json:"used_quota"`
	IsActive   bool       `gorm:"not null;default:true" json:"is_active"`
	IsInvalid  bool       `gorm:"not null;default:false" json:"is_invalid"`
	LastUsedAt *time.Time `json:"last_used_at"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

type RequestLog struct {
	ID                uint      `gorm:"primaryKey" json:"id"`
	RequestID         string    `gorm:"index;not null" json:"request_id"`
	KeyUsed           uint      `gorm:"column:key_used;index" json:"key_used"`
	KeyAlias          string    `json:"key_alias"`
	Endpoint          string    `gorm:"index;not null" json:"endpoint"`
	StatusCode        int       `json:"status_code"`
	LatencyMs         int64     `json:"latency"`
	RequestBody       string    `gorm:"type:text" json:"request_body,omitempty"`
	RequestTruncated  bool      `gorm:"not null;default:false" json:"request_truncated"`
	ResponseBody      string    `gorm:"type:text" json:"response_body,omitempty"`
	ResponseTruncated bool      `gorm:"not null;default:false" json:"response_truncated"`
	CacheHit          bool      `gorm:"not null;default:false" json:"cache_hit"`
	ClientIP          string    `json:"client_ip"`
	CreatedAt         time.Time `gorm:"index" json:"created_at"`
}

type RequestStat struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Granularity string    `gorm:"not null;index:idx_request_stat_bucket,unique" json:"granularity"`
	Bucket      string    `gorm:"not null;index:idx_request_stat_bucket,unique" json:"bucket"`
	Endpoint    string    `gorm:"not null;default:'';index:idx_request_stat_bucket,unique" json:"endpoint"`
	Count       int64     `gorm:"not null;default:0" json:"count"`
	UpdatedAt   time.Time `gorm:"index" json:"updated_at"`
}

type Setting struct {
	Key       string    `gorm:"primaryKey" json:"key"`
	Value     string    `gorm:"not null" json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

type SearchCache struct {
	ID           uint      `gorm:"primaryKey"`
	CacheKey     string    `gorm:"uniqueIndex;not null"`
	Query        string    `gorm:"not null"`
	RequestBody  string    `gorm:"type:text;not null"`
	ResponseBody string    `gorm:"type:text;not null"`
	StatusCode   int       `gorm:"not null"`
	HitCount     int64     `gorm:"not null;default:0"`
	ExpiresAt    time.Time `gorm:"index;not null"`
	CreatedAt    time.Time `gorm:"not null"`
}
