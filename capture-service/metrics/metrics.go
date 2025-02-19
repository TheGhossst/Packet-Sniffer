package metrics

import (
	"sync/atomic"
	"time"
)

// Import PacketData type from main package
type PacketData struct {
	Timestamp   string `json:"timestamp"`
	SrcIP       string `json:"src_ip"`
	DstIP       string `json:"dst_ip"`
	Protocol    string `json:"protocol"`
	SrcPort     uint16 `json:"src_port"`
	DstPort     uint16 `json:"dst_port"`
	PacketSize  int    `json:"packet_size"`
	PacketType  string `json:"packet_type"`
	PayloadSize int    `json:"payload_size"`
}

type Metrics struct {
	PacketsCaptured  uint64
	PacketsDropped   uint64
	BatchesPublished uint64
	ErrorCount       uint64
	ProcessingTime   float64
}

func NewMetrics() *Metrics {
	return &Metrics{}
}

type EnhancedMetrics struct {
	PacketsProcessed   uint64
	BytesProcessed     uint64
	BatchesSent        uint64
	AverageLatency     time.Duration
	DroppedPackets     uint64
	ProcessingErrors   uint64
	RedisErrors        uint64
	AverageBatchSize   float64
	LastProcessingTime time.Time
	NetworkUtilization float64
}

func (m *EnhancedMetrics) Record(packet PacketData) {
	atomic.AddUint64(&m.PacketsProcessed, 1)
	atomic.AddUint64(&m.BytesProcessed, uint64(packet.PacketSize))
	m.LastProcessingTime = time.Now()
	// Calculate network utilization
	m.NetworkUtilization = float64(m.BytesProcessed) / time.Since(m.LastProcessingTime).Seconds()
}
