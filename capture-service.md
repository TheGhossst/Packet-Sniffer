# Network Packet Capture Service

## Overview
The capture service is a high-performance network packet monitoring tool that captures, processes, and analyzes network traffic in real-time. It uses libpcap for packet capture and Redis for distributing packet data to analysis workers.

## Features
- Real-time packet capture
- Automatic network interface detection
- Configurable packet filtering
- Batch processing for better performance
- Redis-based packet distribution
- Graceful shutdown handling
- Detailed packet analysis
- Metrics collection
- Support for multiple protocols (TCP, UDP, ICMP)

## How It Works

### 1. Initialization
```go
func main() {
    cfg := config.LoadConfig()
    // Initialize Redis and packet capture...
}
```
- Loads configuration from environment variables
- Automatically detects available network interfaces
- Establishes Redis connection
- Sets up packet capture on specified interface

### 2. Packet Capture Process
1. **Interface Detection**:
   - Automatically finds available network interfaces
   - Excludes loopback and virtual interfaces
   - Allows manual interface selection via flags

2. **Packet Processing Pipeline**:
   ```
   Network → libpcap → Packet Channel → Batch Processing → Redis → Analysis Workers
   ```

3. **Data Collection**:
   - Captures packet metadata:
     - Source/Destination IPs
     - Ports
     - Protocol
     - Packet size
     - Timestamp
     - Payload information

### 3. Performance Features
- Batch processing (100 packets per batch)
- Channel buffering (1000 packets)
- Periodic flush timer (100ms)
- Efficient memory management
- Concurrent processing

## Configuration

### Environment Variables
```env
CAPTURE_INTERFACE=eth0
REDIS_ADDR=localhost:6379
LOG_LEVEL=info
BATCH_SIZE=100
CHANNEL_SIZE=1000
```

### Command Line Flags
```bash
-interface string    Network interface to capture (default "auto")
-redis string        Redis server address (default "localhost:6379")
```

## Sample Output

```
Available Network Interfaces:
-----------------------------
1. Intel(R) Ethernet Connection
   Name: eth0
   IPs:  [192.168.1.100/24]

Packet #10: 192.168.1.2:56652 -> 162.159.198.1:4443 (IPv4) size=88 bytes
Packet #20: 162.159.198.1:4443 -> 192.168.1.2:56652 (IPv4) size=170 bytes
Packet #30: 192.168.1.2:56652 -> 162.159.198.1:4443 (IPv4) size=152 bytes
```

## Metrics
- Packets processed
- Bytes processed
- Processing time
- Batch statistics
- Error counts

## Usage

1. **Basic Usage**:
   ```bash
   ./capture-service
   ```

2. **Specify Interface**:
   ```bash
   ./capture-service -interface eth0
   ```

3. **Custom Redis**:
   ```bash
   ./capture-service -redis redis.example.com:6379
   ```

## Installation

### Prerequisites
- Go 1.21 or higher
- libpcap-dev
- Redis server

### Build
```bash
go build -o capture-service
```

### Docker
```bash
docker build -t capture-service .
docker run --network host capture-service
```

## Performance Considerations

1. **Memory Usage**:
   - Batch processing reduces memory pressure
   - Channel buffering prevents packet loss
   - Efficient packet struct design

2. **CPU Usage**:
   - Concurrent processing
   - Efficient packet parsing
   - Optimized memory allocation

3. **Network Impact**:
   - Minimal overhead
   - Efficient Redis protocol
   - Batch publishing

## Troubleshooting

### Common Issues
1. **Permission Denied**:
   ```bash
   sudo setcap cap_net_raw+ep ./capture-service
   ```

2. **Interface Not Found**:
   - Check available interfaces with `-list-interfaces`
   - Verify interface name
   - Check permissions

3. **Redis Connection Failed**:
   - Verify Redis server is running
   - Check network connectivity
   - Validate Redis address

## Best Practices

1. **Production Deployment**:
   - Use systemd service
   - Configure proper logging
   - Monitor resource usage
   - Set up alerting

2. **Security**:
   - Run with minimal privileges
   - Use network isolation
   - Secure Redis connection
   - Regular updates

3. **Monitoring**:
   - Watch packet drop rate
   - Monitor memory usage
   - Check processing latency
   - Track error rates

