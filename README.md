# Network Analysis Service

An Netword Analysis Service that combines real-time packet capture with multi-source threat intelligence APIs for comprehensive network security monitoring.

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [System Architecture](#system-architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [Installation of Dependencies](#installation-of-dependencies)
  - [Setting Up Capture Service](#setting-up-capture-service)
  - [Setting Up Analysis Service v2](#setting-up-analysis-service-v2)
  - [Setting Up Frontend](#setting-up-frontend)
- [Configuration](#configuration)
- [Running the System](#running-the-system)
- [API Documentation](#api-documentation)
- [Development](#development)
- [Troubleshooting](#troubleshooting)

## Overview

This Network Analysis Service project integrates real-time packet capture with threat intelligence to provide comprehensive network security monitoring. The system consists of three main components:

1. **Capture Service**: A Go-based service that captures network packets in real-time
2. **Analysis Service v2**: A Node.js service that analyzes captured packets against various threat intelligence sources
3. **Frontend**: A Next.js web application that displays the analysis results and system metrics

## Features

### Capture Service Features
- Real-time packet capture and analysis
- Support for both IPv4 and IPv6
- Protocol-specific validation
- Packet filtering based on configurable rules
- High-performance packet processing
- Redis integration for packet queueing

### Analysis Service v2 Features
- **Enhanced Threat Intelligence**
  - Direct integration with [stamparm/ipsum](https://github.com/stamparm/ipsum) repository for malicious IP detection
  - Local caching of malicious IP database
  - Score-based threat level determination
  - Automatic 24-hour refresh cycle
  - Detailed logging of database updates

- **Safe IP Management**
  - Maintain and persist a list of trusted IP addresses
  - Automatically exclude safe IPs from malicious detection
  - Add/remove IPs from the safe list via API
  - Persistence across service restarts

- **Improved Status Display**
  - Clear "Safe" or "Unsafe" status indicators (replacing the previous "BENIGN"/"MALICIOUS" labels)
  - Detailed threat level reporting
  - Enhanced logging for all detection events

- **Advanced Error Handling**
  - Comprehensive error handling for API failures
  - Graceful degradation when services are unavailable
  - Detailed error logging with context
  - Timeout management for external API requests
  - Error classification and metrics tracking
  - Automatic fallback to alternative data sources
  - Self-healing design that continues functioning during API outages

- **Performance Features**
  - In-memory caching for reputation data
  - Configurable TTL (default: 1 hour)
  - Cache hit/miss metrics
  - Rate limiting with token bucket algorithm

### Frontend Features
- Real-time packet monitoring dashboard
- Threat visualization and statistics
- Detailed packet inspection views
- Service metrics and performance monitoring
- Responsive design for various device sizes
- Dark/light mode support

## System Architecture

```
┌─────────────────┐      ┌──────────────────┐      ┌────────────────┐
│                 │      │                  │      │                │
│  Capture        │─────▶│  Analysis        │─────▶│  Frontend      │
│  Service (Go)   │      │  Service v2 (TS) │      │  (Next.js)     │
│                 │      │                  │      │                │
└─────────────────┘      └──────────────────┘      └────────────────┘
        │                         │                        │
        │                         │                        │
        ▼                         ▼                        ▼
┌─────────────────┐      ┌──────────────────┐      ┌────────────────┐
│  Network        │      │  Threat Intel    │      │  User          │
│  Interface      │      │  Sources         │      │  Interface     │
│                 │      │  (Ipsum Feed)    │      │                │
└─────────────────┘      └──────────────────┘      └────────────────┘
```

### Data Flow
1. Capture Service monitors network interfaces and captures packets
2. Captured packets are sent to Analysis Service v2
3. Analysis Service v2 checks packets against threat intelligence sources
4. Results are formatted with "Safe" or "Unsafe" status
5. Frontend displays the results in real-time

## Prerequisites

### System Requirements
- **Operating System**: Windows 10/11, Linux (Ubuntu 18.04+ recommended), or macOS 10.15+
- **RAM**: Minimum 4GB, recommended 8GB+
- **Disk Space**: At least 1GB free space
- **Network**: Administrative access to network interfaces

### Software Requirements
- **Go**: v1.17 or later
  - [Download Go](https://golang.org/dl/)
  - Verify installation: `go version`

- **Node.js**: v16.0 or later (v18+ recommended)
  - [Download Node.js](https://nodejs.org/en/download/)
  - Verify installation: `node -v` and `npm -v`

- **Redis**: v6.0 or later
  - Windows: [Download Redis for Windows](https://github.com/tporadowski/redis/releases)
  - Linux: `sudo apt install redis-server`
  - macOS: `brew install redis`
  - Or use Docker: `docker run --name redis -p 6379:6379 -d redis`
  - Verify installation: `redis-cli ping` (should return "PONG")

- **Npcap** (for Windows):
  - [Download from Npcap website](https://npcap.com/#download)
  - Install with WinPcap compatibility mode

- **libpcap** (for Linux/macOS):
  - Linux: `sudo apt-get install libpcap-dev`
  - macOS: `brew install libpcap`

- **Git**:
  - [Download Git](https://git-scm.com/downloads)
  - Verify installation: `git --version`

- **Docker** (optional, for containerized deployment):
  - [Download Docker](https://www.docker.com/products/docker-desktop)
  - Verify installation: `docker --version`

## Installation

### Installation of Dependencies

#### 1. Clone the Repository
```bash
git clone https://github.com/TheGhossst/Packet-Sniffer.git
cd Packet-Sniffer
```

#### 2. Install Global Dependencies (if not already installed)
```bash
# Install TypeScript globally
npm install -g typescript

# Install nodemon for development (optional)
npm install -g nodemon
```

### Setting Up Capture Service

The capture service is written in Go and responsible for capturing network packets.

#### 1. Navigate to the Capture Service Directory
```bash
cd capture-service
```

#### 2. Install Go Dependencies
```bash
go mod download
```

#### 3. Build the Capture Service
```bash
go build -o capture-service main.go
```

#### 4. Configure Capture Service
Create a configuration file in the `config` directory if it doesn't exist:
```bash
# For Windows
copy config\config.example.json config\config.json

# For Linux/macOS
cp config/config.example.json config/config.json
```
Edit the configuration file to specify your network interface and other settings.
#### 5. Run Capture Service
```bash
.\capture-service.exe
```
### Setting Up Analysis Service v2

The analysis service v2 is a Node.js application that processes and analyzes the captured packets.

#### 1. Navigate to the Analysis Service v2 Directory
```bash
cd ../analysis-service-2
```

#### 2. Install Node.js Dependencies
```bash
npm install
```

#### 3. Create Data Directories
Ensure the data directories exist:
```bash
# For Windows
mkdir -p data\safe-ips
mkdir -p data\ipsum-feed

# For Linux/macOS
mkdir -p data/safe-ips
mkdir -p data/ipsum-feed
```

#### 4. Start the Analysis Service
```bash
npm run start
```

### Setting Up Frontend

The frontend is a Next.js application that provides the user interface.

#### 1. Navigate to the Frontend Directory
```bash
cd ../frontend
```

#### 2. Install Node.js Dependencies
```bash
npm install
```

#### 3. Build the Next.js Application
```bash
npm run dev
```

## Configuration

### Capture Service Configuration
Edit the `capture-service/config/config.json` file:

```json
{
  "interface": "your-interface-name",  // e.g., "eth0" for Linux, "Ethernet" for Windows
  "promiscuous": true,
  "snaplen": 1600,
  "redis": {
    "host": "localhost",
    "port": 6379,
    "password": "",
    "db": 0
  },
  "filters": {
    "enabled": true,
    "file": "filters/default.json"
  },
  "metrics": {
    "enabled": true,
    "port": 9090
  }
}
```

### Analysis Service v2 Configuration
Create a `.env` file in the `analysis-service-2` directory:

```ini
# Analysis Service v2 Configuration
PORT=3001
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
IPSUM_FEED_URL=https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt
IPSUM_REFRESH_INTERVAL=86400000  # 24 hours in milliseconds
SAFE_IPS_FILE=./data/safe-ips/safe-ips.json
```

### Frontend Configuration
Create a `.env.local` file in the `frontend` directory:

```ini
# Frontend Configuration
NEXT_PUBLIC_API_URL=http://localhost:3001
NEXT_PUBLIC_METRICS_URL=http://localhost:9090
```

## Running the System

### Running with Docker Compose (Recommended)
If you have Docker installed, you can use Docker Compose to run all services:

```bash
# From the project root directory
docker-compose up -d
```

### Running Services Individually

#### 1. Start Redis
```bash
# If installed as a service
sudo service redis-server start  # Linux
brew services start redis  # macOS

# Or run with Docker
docker run --name redis -p 6379:6379 -d redis
```

#### 2. Start the Capture Service
```bash
# Navigate to capture-service directory
cd capture-service

# Run the service (Windows)
.\capture-service.exe

# Run the service (Linux/macOS)
sudo ./capture-service  # sudo is needed for network interface access
```

#### 3. Start the Analysis Service v2
```bash
# Navigate to analysis-service-2 directory
cd analysis-service-2

# Run in production mode
npm start

# Or run in development mode
npm run dev
```

#### 4. Start the Frontend
```bash
# Navigate to frontend directory
cd frontend

# Run in production mode
npm start

# Or run in development mode
npm run dev
```

### Access the Application
Open your browser and navigate to:
- Frontend: [http://localhost:3000](http://localhost:3000)
- Analysis Service API: [http://localhost:3001](http://localhost:3001)
- Metrics (if enabled): [http://localhost:9090](http://localhost:9090)

## API Documentation

### Analysis Service v2 API Endpoints

#### Check Packet Status
```
GET /api/check-packet
```
Request body:
```json
{
  "sourceIp": "192.168.1.1",
  "destinationIp": "8.8.8.8",
  "sourcePort": 54321,
  "destinationPort": 80,
  "protocol": "TCP"
}
```

Response:
```json
{
  "status": "Safe", // or "Unsafe"
  "threatLevel": "LOW", // "LOW", "MEDIUM", "HIGH", "CRITICAL"
  "reason": {
    "source": "ipsum-feed",
    "score": 0.4,
    "details": "IP found in malicious database with score 4/10"
  }
}
```

#### Manage Safe IPs

Add IP to safe list:
```
POST /api/safe-ips
```
Request body:
```json
{
  "ip": "192.168.1.5"
}
```

Remove IP from safe list:
```
DELETE /api/safe-ips/:ip
```

Get all safe IPs:
```
GET /api/safe-ips
```

## Development

### Development Workflow

#### Capture Service
```bash
cd capture-service
go run main.go
```

#### Analysis Service v2
```bash
cd analysis-service-2
npm run dev
```

#### Frontend
```bash
cd frontend
npm run dev
```

### Testing

#### Capture Service
```bash
cd capture-service
go test ./...
```

#### Analysis Service v2
```bash
cd analysis-service-2
npm test
```

#### Frontend
```bash
cd frontend
npm test
```

## Troubleshooting

### Common Issues

#### Capture Service

**Issue**: Permission denied when accessing network interfaces
**Solution**: Run with administrative privileges (sudo on Linux/macOS)

**Issue**: Cannot find network interfaces
**Solution**: 
- Verify Npcap/libpcap installation
- Check interface names with `ipconfig` (Windows) or `ifconfig`/`ip a` (Linux/macOS)

#### Analysis Service v2

**Issue**: Cannot connect to Redis
**Solution**: 
- Verify Redis is running: `redis-cli ping`
- Check connection settings in `.env` file

**Issue**: Error fetching from Ipsum Feed
**Solution**: 
- Check internet connectivity
- Verify the Ipsum Feed URL in the configuration

#### Frontend

**Issue**: Cannot connect to API
**Solution**: 
- Ensure Analysis Service v2 is running
- Check API URL in `.env.local` file

### Logs

- Capture Service logs: Output to console and `capture-service/logs` directory
- Analysis Service v2 logs: Output to console and `analysis-service-2/logs` directory
- Frontend logs: Available in browser console and Next.js logs

For more detailed troubleshooting, check the console output or log files of the respective services.