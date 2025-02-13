package config

import (
	"os"
	"time"

	"github.com/google/gopacket/pcap"
)

type Config struct {
	Interface   string
	RedisAddr   string
	SnapshotLen int32
	Promiscuous bool
	Timeout     time.Duration
}

func NewConfig() *Config {
	return &Config{
		Interface:   getEnv("CAPTURE_INTERFACE", "eth0"),
		RedisAddr:   getEnv("REDIS_ADDR", "localhost:6379"),
		SnapshotLen: 1024,
		Promiscuous: true,
		Timeout:     pcap.BlockForever,
	}
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
