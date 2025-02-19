package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"

	"ids/capture-service/config"

	"ids/capture-service/filters"
	"ids/capture-service/types"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/redis/go-redis/v9"
)

type PacketData = types.PacketData

var (
	device      string
	redisAddr   string
	packetCount int
)

type PacketBatch struct {
	Packets   []PacketData `json:"packets"`
	Timestamp time.Time    `json:"timestamp"`
}

type Config struct {
	SampleRate int
}

type PacketMetrics struct {
	PacketsProcessed uint64
	BytesProcessed   uint64
	BatchesSent      uint64
	AverageLatency   time.Duration
	RedisErrors      uint64
}

type PacketBuffer struct {
	buffer    []types.PacketData
	batchSize int
	metrics   *PacketMetrics
	filter    *filters.PacketFilter
}

func NewPacketBuffer(batchSize int) *PacketBuffer {
	return &PacketBuffer{
		buffer:    make([]types.PacketData, 0, batchSize),
		batchSize: batchSize,
		metrics:   &PacketMetrics{},
		filter:    filters.NewPacketFilter(),
	}
}

func (pb *PacketBuffer) Add(packet PacketData) ([]PacketData, bool) {
	if !pb.filter.ShouldProcess(packet) {
		return nil, false
	}

	pb.buffer = append(pb.buffer, packet)
	if len(pb.buffer) >= pb.batchSize {
		batch := pb.buffer
		pb.buffer = make([]types.PacketData, 0, pb.batchSize)
		return batch, true
	}
	return nil, false
}

func init() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("Error finding devices: %v", err)
	}

	printInterfaceDetails(devices)
	defaultInterface := ""
	for _, dev := range devices {
		if strings.Contains(dev.Description, "Loopback") ||
			strings.Contains(dev.Description, "Virtual") {
			continue
		}
		for _, addr := range dev.Addresses {
			ip := addr.IP.String()
			if !strings.HasPrefix(ip, "169.254.") && !strings.HasPrefix(ip, "fe80::") {
				defaultInterface = dev.Name
				break
			}
		}
		if defaultInterface != "" {
			break
		}
	}

	if defaultInterface == "" && len(devices) > 0 {
		defaultInterface = devices[0].Name
	}

	flag.StringVar(&device, "interface", defaultInterface, "Network interface to capture")
	flag.StringVar(&redisAddr, "redis", "localhost:6379", "Redis server address")
	flag.Parse()
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	shutdown := make(chan struct{})
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		log.Println("Initiating graceful shutdown...")
		cancel()

		time.Sleep(time.Second * 2)
		close(shutdown)
	}()

	cfg := config.LoadConfig()

	rdb := redis.NewClient(&redis.Options{
		Addr: cfg.RedisAddr,
	})
	defer rdb.Close()

	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}

	iface := cfg.Interface
	if iface == "" {
		iface = findDefaultInterface()
	}

	handle, err := pcap.OpenLive(iface, cfg.SnapshotLen, cfg.Promiscuous, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Failed to open device %s: %v", iface, err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	packets := make(chan PacketData, 1000)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		processPackets(ctx, packets, rdb)
	}()

	go func() {
		for packet := range packetSource.Packets() {
			data := parsePacket(packet)
			if data != nil {
				packets <- *data
			}
		}
	}()

	<-shutdown
	log.Println("Shutting down...")
	close(packets)
	wg.Wait()
}

func processPackets(ctx context.Context, packets <-chan PacketData, rdb *redis.Client) {
	buffer := NewPacketBuffer(100)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	var metrics PacketMetrics

	for {
		select {
		case <-ctx.Done():
			return
		case packet, ok := <-packets:
			if !ok {
				return
			}
			if batch, ready := buffer.Add(packet); ready {
				if err := publishBatch(ctx, rdb, batch, &metrics); err != nil {
					log.Printf("Error publishing batch: %v", err)
					atomic.AddUint64(&metrics.RedisErrors, 1)
				}
			}
		case <-ticker.C:
			if len(buffer.buffer) > 0 {
				if err := publishBatch(ctx, rdb, buffer.buffer, &metrics); err != nil {
					log.Printf("Error publishing partial batch: %v", err)
					atomic.AddUint64(&metrics.RedisErrors, 1)
				}
				buffer.buffer = buffer.buffer[:0]
			}
		}
	}
}

func publishBatch(ctx context.Context, rdb *redis.Client, batch []PacketData, metrics *PacketMetrics) error {
	startTime := time.Now()
	data := map[string]interface{}{
		"packets":   batch,
		"timestamp": time.Now(),
		"batchId":   uuid.New().String(),
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("batch marshaling error: %w", err)
	}

	if err := rdb.Publish(ctx, "packet-stream", jsonData).Err(); err != nil {
		return fmt.Errorf("redis publish error: %w", err)
	}

	latency := time.Since(startTime)
	atomic.StoreInt64((*int64)(&metrics.AverageLatency), int64(latency))

	return nil
}

func processPacketData(packet gopacket.Packet) (PacketData, error) {
	pd := PacketData{
		Timestamp:   packet.Metadata().Timestamp.Format(time.RFC3339),
		PacketSize:  len(packet.Data()),
		PacketType:  "Unknown",
		PayloadSize: 0,
	}

	if len(packet.Layers()) > 0 {
		pd.PacketType = packet.Layers()[0].LayerType().String()
	}

	if networkLayer := packet.NetworkLayer(); networkLayer != nil {
		pd.SrcIP = networkLayer.NetworkFlow().Src().String()
		pd.DstIP = networkLayer.NetworkFlow().Dst().String()
		pd.Protocol = networkLayer.LayerType().String()
	} else {
		if linkLayer := packet.LinkLayer(); linkLayer != nil {
			pd.Protocol = linkLayer.LayerType().String()
		}
	}

	if transportLayer := packet.TransportLayer(); transportLayer != nil {
		pd.SrcPort = uint16(transportLayer.TransportFlow().Src().Raw()[0])<<8 |
			uint16(transportLayer.TransportFlow().Src().Raw()[1])
		pd.DstPort = uint16(transportLayer.TransportFlow().Dst().Raw()[0])<<8 |
			uint16(transportLayer.TransportFlow().Dst().Raw()[1])
	}

	if applicationLayer := packet.ApplicationLayer(); applicationLayer != nil {
		pd.PayloadSize = len(applicationLayer.Payload())
	}

	// Log only every 10th packet
	packetCount++
	if packetCount%10 == 0 {
		log.Printf("Packet #%d: %s:%d -> %s:%d (%s) size=%d bytes",
			packetCount,
			pd.SrcIP,
			pd.SrcPort,
			pd.DstIP,
			pd.DstPort,
			pd.Protocol,
			pd.PacketSize)
	}

	return pd, nil
}

func printInterfaceDetails(devices []pcap.Interface) {
	fmt.Println("\nAvailable Network Interfaces:")
	fmt.Println("-----------------------------")
	for i, device := range devices {
		fmt.Printf("%d. %s\n", i+1, device.Description)
		fmt.Printf("   Name: %s\n", device.Name)
		if len(device.Addresses) > 0 {
			fmt.Printf("   IPs:  %v\n", device.Addresses)
		}
		fmt.Println()
	}
	fmt.Println("Use -interface flag to specify an interface by name")
	fmt.Println("Example: -interface \"" + devices[0].Name + "\"")
	fmt.Println()
}

func findDefaultInterface() string {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("Error finding devices: %v", err)
	}

	for _, dev := range devices {
		if strings.Contains(dev.Description, "Loopback") ||
			strings.Contains(dev.Description, "Virtual") {
			continue
		}
		for _, addr := range dev.Addresses {
			ip := addr.IP.String()
			if !strings.HasPrefix(ip, "169.254.") && !strings.HasPrefix(ip, "fe80::") {
				return dev.Name
			}
		}
	}

	return devices[0].Name
}

func parsePacket(packet gopacket.Packet) *PacketData {
	pd, err := processPacketData(packet)
	if err != nil {
		log.Printf("Error processing packet data: %v", err)
		return nil
	}
	return &pd
}
