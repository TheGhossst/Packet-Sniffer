package redis

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type Client struct {
	client         *redis.Client
	reconnectDelay time.Duration
}

func NewClient(addr string) *Client {
	return &Client{
		client: redis.NewClient(&redis.Options{
			Addr: addr,
		}),
		reconnectDelay: time.Second * 5,
	}
}

func (c *Client) EnsureConnection(ctx context.Context) error {
	for {
		err := c.client.Ping(ctx).Err()
		if err == nil {
			return nil
		}

		time.Sleep(c.reconnectDelay)
		c.client = redis.NewClient(&redis.Options{
			Addr: c.client.Options().Addr,
		})
	}
}
