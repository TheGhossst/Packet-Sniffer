package config

import (
	"errors"
	"os"
	"time"
)

type Config struct {
	Interface       string
	RedisAddr       string
	SnapshotLen     int32
	Promiscuous     bool
	BatchSize       int
	ChannelSize     int
	MetricsPort     int
	LogLevel        string
	BPFFilter       string
	FilterPorts     []uint16 `json:"filter_ports"`
	FilterProtocols []string `json:"filter_protocols"`
	FilterIPs       []string `json:"filter_ips"`
}

type EnhancedConfig struct {
	Interface      string
	RedisAddr      string
	SnapshotLen    int32
	Promiscuous    bool
	BatchSize      int
	ChannelSize    int
	MetricsPort    int
	LogLevel       string
	BPFFilter      string
	FilterPorts    []uint16
	FilterIPs      []string
	RetryAttempts  int
	RetryDelay     time.Duration
	MaxBatchDelay  time.Duration
	MetricsEnabled bool
}

func (c *Config) Validate() error {
	if c.BatchSize < 1 {
		return errors.New("batch size must be positive")
	}
	if c.ChannelSize < c.BatchSize {
		return errors.New("channel size must be >= batch size")
	}
	return nil
}

func LoadConfig() *Config {
	return &Config{
		Interface:       os.Getenv("CAPTURE_INTERFACE"),
		RedisAddr:       getEnvOrDefault("REDIS_ADDR", "localhost:6379"),
		SnapshotLen:     1024,
		Promiscuous:     true,
		BatchSize:       100,
		ChannelSize:     1000,
		MetricsPort:     8080,
		LogLevel:        getEnvOrDefault("LOG_LEVEL", "info"),
		FilterPorts:     []uint16{80, 443, 22, 53},
		FilterProtocols: []string{"TCP", "UDP", "ICMP"},
		FilterIPs:       []string{},
		BPFFilter:       "tcp or udp or icmp",
	}
}

func LoadEnhancedConfig() *EnhancedConfig {
	return &EnhancedConfig{
		Interface:      os.Getenv("CAPTURE_INTERFACE"),
		RedisAddr:      getEnvOrDefault("REDIS_ADDR", "localhost:6379"),
		SnapshotLen:    1024,
		Promiscuous:    true,
		BatchSize:      100,
		ChannelSize:    1000,
		MetricsPort:    8080,
		LogLevel:       getEnvOrDefault("LOG_LEVEL", "info"),
		FilterPorts:    []uint16{80, 443, 22, 53},
		FilterIPs:      []string{},
		BPFFilter:      "tcp or udp or icmp",
		RetryAttempts:  3,
		RetryDelay:     time.Second * 2,
		MaxBatchDelay:  time.Millisecond * 500,
		MetricsEnabled: true,
	}
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
