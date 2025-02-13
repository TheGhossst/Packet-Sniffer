# Network IDS with Threat Intelligence

An Intrusion Detection System (IDS) that combines real-time packet capture with threat intelligence APIs.

## Prerequisites

- Go (latest stable version)
- Node.js
- Redis
- Npcap (for Windows)
- Docker (optional)

## Setup Instructions

1. Install Npcap:
   - Download from [Npcap website](https://npcap.com/#download)
   - Install with WinPcap compatibility mode

2. Install Redis:
   ```bash
   # Using Docker
   docker run --name redis -p 6379:6379 -d redis
   
   # Or install locally on Windows
   # Download from https://redis.io/download
   ```

3. Install Go dependencies:
   ```bash
   cd capture-service
   go mod init ids/capture-service
   go get github.com/google/gopacket
   go get github.com/google/gopacket/pcap
   go get github.com/redis/go-redis/v9
   ```

4. Install Node.js dependencies:
   ```bash
   cd analysis-worker
   npm init -y
   npm install redis
   ```

## Project Structure

- `/capture-service` - Go-based packet capture service
- `/analysis-worker` - Node.js-based analysis worker
- `/config` - Configuration files
- `/docker` - Docker-related files 