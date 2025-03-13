# Network IDS with Threat Intelligence

An advanced Intrusion Detection System (IDS) that combines real-time packet capture with multi-source threat intelligence APIs for comprehensive network security monitoring.

## Table of Contents
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Setup Instructions](#setup-instructions)
- [Architecture](#architecture)
  - [Core Components](#core-components)
  - [Threat Intelligence Integration](#threat-intelligence-integration)
  - [Analysis Pipeline](#analysis-pipeline)
- [API Documentation](#api-documentation)
- [Configuration](#configuration)
- [Monitoring](#monitoring)
- [Development](#development)

## Features

### 1. Advanced Packet Analysis
- Real-time packet capture and analysis
- Support for both IPv4 and IPv6
- Protocol-specific validation
- Port scanning detection
- DoS/DDoS attack detection
- Brute force attempt detection
- Traffic pattern analysis

### 2. Multi-Source Threat Intelligence
- **Ipsum Feed Integration (40% weight)**
  - Direct integration with [stamparm/ipsum](https://github.com/stamparm/ipsum) repository
  - Local caching of malicious IP database
  - Score-based threat level determination
  - Automatic 24-hour refresh cycle
  - Safe IP list management

- **AbuseIPDB Integration (30% weight)**
  - Confidence scoring (0-100)
  - Historical abuse reports
  - Community-driven reporting

- **VirusTotal Integration (30% weight)**
  - Multi-engine detection
  - File and URL scanning
  - Comprehensive threat data

### 3. Sophisticated Scoring System
- **Composite Reputation Scoring**
  ```typescript
  compositeScore = (
    ipsumFeed * 0.4 +
    abuseIPDB * 0.3 +
    virusTotal * 0.3
  )
  ```

- **Alert Severity Thresholds**
  - CRITICAL: Score ≥ 0.85 (requires 3+ sources)
  - HIGH: Score ≥ 0.70 (requires 2+ sources)
  - MEDIUM: Score ≥ 0.50 (requires 2+ sources)
  - LOW: Score ≥ 0.30 (requires 1+ source)

### 4. Status Indicators
- **Clear Status Display**
  - "Safe" status for trusted or non-malicious IPs
  - "Unsafe" status for known malicious IPs
  - Detailed threat level descriptions
  - Source identification (Ipsum feed, safe list)

### 5. Advanced Error Handling
- Custom error types for different scenarios
- Detailed error context
- Error chaining
- Structured logging

### 6. Performance Features
- **Caching System**
  - In-memory caching for reputation data
  - Configurable TTL (default: 1 hour)
  - Cache hit/miss metrics

- **Rate Limiting**
  - Token bucket algorithm
  - Configurable limits per API
  - Burst handling
  - Automatic backoff

- **Retry Mechanism**
  - Exponential backoff
  - Configurable retry attempts
  - Timeout handling
  - Circuit breaking

- **IP Safelist Management**
  - Persistent storage of trusted IPs
  - Add/remove APIs for safe IP management
  - Automatic exclusion from threat checks
  - Regular backup of safe IP database

### 7. Traffic Pattern Analysis
- **Pattern Detection**
  - Port scanning patterns
  - DoS/DDoS patterns
  - Brute force patterns
  - Suspicious port combinations

- **Service Recognition**
  - Well-known service detection
  - Protocol validation
  - Port-protocol correlation

### 8. Metrics and Monitoring
- **Detailed Metrics**
  - API performance metrics
  - Cache efficiency metrics
  - Processing time metrics
  - Alert distribution metrics

- **Source Performance Tracking**
  - True/false positive tracking
  - Source accuracy metrics
  - Dynamic weight adjustment

## Prerequisites

- Go (latest stable version)
- Node.js (v18+)
- Redis
- Npcap (for Windows)
- Docker (optional)

## Setup Instructions

1. Install Npcap:
   ```bash
   # Download from Npcap website
   https://npcap.com/#download
   # Install with WinPcap compatibility mode
   ```

2. Install Redis:
   ```bash
   # Using Docker
   docker run --name redis -p 6379:6379 -d redis
   ```

3. Configure Environment Variables:
   ```bash
   # Analysis Service
   cp analysis-service/.env.example analysis-service/.env
   # Edit .env with your API keys and configuration
   ```

4. Start Services:
   ```bash
   # Using Docker Compose
   docker-compose up -d
   ```

## Architecture

### Core Components

1. **Capture Service**
   - Network packet capture
   - Initial packet filtering
   - Packet batching and queueing

2. **Analysis Service**
   - Packet validation and normalization
   - Traffic pattern analysis
   - Threat intelligence integration
   - Alert generation

3. **Analysis Service 2.0**
   - Enhanced threat detection with Ipsum feed
   - Safe/Unsafe status indicators
   - IP safelist management
   - Improved logging and reporting

4. **Alert Service**
   - Alert aggregation
   - Alert persistence
   - Notification dispatch

### Analysis Pipeline

1. **Packet Ingestion**
   ```typescript
   async analyzePacket(rawPacket: any) {
     // Packet validation
     // Traffic pattern analysis
     // Reputation checks
     // Alert generation
   }
   ```

2. **Reputation Analysis**
   ```typescript
   private async performReputationAnalysis(packet: PacketData) {
     // Multi-source reputation checks
     // Composite score calculation
     // Alert threshold evaluation
   }
   ```

3. **Pattern Detection**
   ```typescript
   private async validateTrafficPattern(packet: PacketData) {
     // Port scan detection
     // DoS detection
     // Brute force detection
   }
   ```

## API Documentation

### Analysis Service API

#### Analyze Packet
```http
POST /api/analysis/packet
Content-Type: application/json

{
    "src_ip": "192.168.1.100",
    "dst_ip": "10.0.0.1",
    "protocol": "TCP",
    "src_port": 12345,
    "dst_port": 80,
    "packet_size": 1024,
    "packet_type": "SYN",
    "timestamp": "2024-03-10T15:00:00Z"
}
```

#### Get Analysis Metrics
```http
GET /api/analysis/metrics
```

## Configuration

### Analysis Service Configuration
```env
# API Keys
IPSUM_FEED_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
VIRUSTOTAL_API_KEY=your_key

# Analysis Configuration
ANALYSIS_WORKERS=4
BATCH_SIZE=100
CACHE_TTL=3600000

# Rate Limiting
RATE_LIMIT_MAX_REQUESTS=60
RATE_LIMIT_WINDOW_MS=60000
RATE_LIMIT_MAX_BURST=10

# Retry Configuration
RETRY_MAX_ATTEMPTS=3
RETRY_INITIAL_DELAY=1000
RETRY_MAX_DELAY=5000
RETRY_BACKOFF_FACTOR=2
```

## Monitoring

### Available Metrics

1. **Performance Metrics**
   - Packet processing time
   - API response times
   - Cache hit/miss ratios
   - Rate limit statistics

2. **Threat Metrics**
   - Detected threats by type
   - Alert severity distribution
   - Source reliability scores
   - False positive rates

3. **System Metrics**
   - Memory usage
   - CPU utilization
   - Network bandwidth
   - Error rates

### Grafana Integration
- Pre-configured dashboards available
- Real-time metric visualization
- Alert tracking and analysis
- Performance monitoring

## Development

### Running Tests
```bash
# Analysis Service
cd analysis-service
npm test

# Capture Service
cd capture-service
go test ./...
```

### Building
```bash
# Analysis Service
cd analysis-service
npm run build

# Capture Service
cd capture-service
go build
```

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.