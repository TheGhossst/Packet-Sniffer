package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestRedisConnection(t *testing.T) {
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	defer rdb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Errorf("Failed to connect to Redis: %v", err)
	}
}

func TestPacketDataSerialization(t *testing.T) {
	pd := PacketData{
		Timestamp:   time.Now().Format(time.RFC3339),
		SrcIP:       "192.168.1.1",
		DstIP:       "192.168.1.2",
		Protocol:    "TCP",
		SrcPort:     80,
		DstPort:     443,
		PacketSize:  100,
		PacketType:  "IPv4",
		PayloadSize: 50,
	}

	_, err := json.Marshal(pd)
	if err != nil {
		t.Errorf("Failed to marshal PacketData: %v", err)
	}
}
