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
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/redis/go-redis/v9"
)

// PacketData represents the structure of our captured packet data
type PacketData struct {
	Timestamp   time.Time `json:"timestamp"`
	SrcIP       string    `json:"src_ip"`
	DstIP       string    `json:"dst_ip"`
	Protocol    string    `json:"protocol"`
	SrcPort     uint16    `json:"src_port"`
	DstPort     uint16    `json:"dst_port"`
	PacketSize  int       `json:"packet_size"`
	PacketType  string    `json:"packet_type"`
	PayloadSize int       `json:"payload_size"`
}

var (
	device      string
	snapshotLen int32 = 1024
	promiscuous bool  = true
	timeout     time.Duration
	redisAddr   string
	packetCount int
)

const (
	batchSize    = 100
	batchTimeout = 500 * time.Millisecond
)

type PacketBatch struct {
	Packets   []PacketData `json:"packets"`
	Timestamp time.Time    `json:"timestamp"`
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
	flag.DurationVar(&timeout, "timeout", pcap.BlockForever, "Capture timeout")
	flag.Parse()
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("Starting packet capture on interface: %s\n", device)

	// Initialize Redis client
	rdb := redis.NewClient(&redis.Options{
		Addr: redisAddr,
	})
	defer rdb.Close()

	// Test Redis connection
	ctx := context.Background()
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	log.Println("Successfully connected to Redis")

	// Open device for capturing
	handle, err := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatalf("Error opening device %s: %v", device, err)
	}
	defer handle.Close()

	// Use a more permissive BPF filter to capture more types of packets
	err = handle.SetBPFFilter("") // Empty filter to capture all packets
	if err != nil {
		log.Printf("Warning: Could not set BPF filter: %v", err)
	}

	// Add statistics logging
	go func() {
		for {
			time.Sleep(5 * time.Second)
			stats, err := handle.Stats()
			if err != nil {
				log.Printf("Error getting stats: %v", err)
				continue
			}
			log.Printf("Packets received: %d, dropped: %d, interface dropped: %d",
				stats.PacketsReceived, stats.PacketsDropped, stats.PacketsIfDropped)
		}
	}()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	log.Println("Starting packet capture...")
	packetChan := packetSource.Packets()

	batchChan := make(chan PacketData, batchSize)
	done := make(chan bool)

	go processBatches(ctx, batchChan, rdb, done)

	// Modify the packet processing loop
	for {
		select {
		case packet := <-packetChan:
			if packet == nil {
				continue
			}
			// Process packet and send to batch channel
			pd, err := processPacketData(packet)
			if err != nil {
				log.Printf("Error processing packet data: %v", err)
				continue
			}
			batchChan <- pd

		case <-signalChan:
			log.Println("Shutting down...")
			close(batchChan)
			<-done // Wait for batch processor to finish
			return
		}
	}
}

func processBatches(ctx context.Context, batchChan chan PacketData, rdb *redis.Client, done chan bool) {
	defer close(done)

	var batch []PacketData
	ticker := time.NewTicker(batchTimeout)
	defer ticker.Stop()

	for {
		select {
		case packet, ok := <-batchChan:
			if !ok {
				// Channel closed, flush remaining packets
				if len(batch) > 0 {
					publishBatch(ctx, batch, rdb)
				}
				return
			}

			batch = append(batch, packet)
			if len(batch) >= batchSize {
				publishBatch(ctx, batch, rdb)
				batch = make([]PacketData, 0, batchSize)
			}

		case <-ticker.C:
			if len(batch) > 0 {
				publishBatch(ctx, batch, rdb)
				batch = make([]PacketData, 0, batchSize)
			}
		}
	}
}

func publishBatch(ctx context.Context, batch []PacketData, rdb *redis.Client) {
	pb := PacketBatch{
		Packets:   batch,
		Timestamp: time.Now(),
	}

	packetJSON, err := json.Marshal(pb)
	if err != nil {
		log.Printf("Error marshaling batch: %v", err)
		return
	}

	err = rdb.Publish(ctx, "packet-stream", packetJSON).Err()
	if err != nil {
		log.Printf("Error publishing batch: %v", err)
	}
}

func processPacketData(packet gopacket.Packet) (PacketData, error) {
	pd := PacketData{
		Timestamp:   packet.Metadata().Timestamp,
		PacketSize:  len(packet.Data()),
		PacketType:  "Unknown",
		PayloadSize: 0,
	}

	if len(packet.Layers()) > 0 {
		pd.PacketType = packet.Layers()[0].LayerType().String()
	}

	// Extract network layer info if available
	if networkLayer := packet.NetworkLayer(); networkLayer != nil {
		pd.SrcIP = networkLayer.NetworkFlow().Src().String()
		pd.DstIP = networkLayer.NetworkFlow().Dst().String()
		pd.Protocol = networkLayer.LayerType().String()
	} else {
		// Handle link layer info if network layer is not available
		if linkLayer := packet.LinkLayer(); linkLayer != nil {
			pd.Protocol = linkLayer.LayerType().String()
		}
	}

	// Extract transport layer info if available
	if transportLayer := packet.TransportLayer(); transportLayer != nil {
		pd.SrcPort = uint16(transportLayer.TransportFlow().Src().Raw()[0])<<8 |
			uint16(transportLayer.TransportFlow().Src().Raw()[1])
		pd.DstPort = uint16(transportLayer.TransportFlow().Dst().Raw()[0])<<8 |
			uint16(transportLayer.TransportFlow().Dst().Raw()[1])
	}

	// Set payload size if application layer exists
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
