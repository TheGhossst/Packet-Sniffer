# Analysis Service 2.0

An enhanced network traffic analysis service with improved threat intelligence capabilities for the Network IDS.

## Features

### Core Functionality
- Real-time packet analysis and threat detection
- Comprehensive IP reputation checking
- Configurable threat level identification
- Detailed packet information formatting

### Enhanced Threat Intelligence
- **Ipsum Feed Integration**
  - Direct integration with [stamparm/ipsum](https://github.com/stamparm/ipsum) repository
  - Local caching of malicious IP database
  - Score-based threat level determination
  - Automatic 24-hour refresh cycle
  - Detailed logging of database updates

### Safe IP Management
- Maintain and persist a list of trusted IP addresses
- Automatically exclude safe IPs from malicious detection
- Add/remove IPs from the safe list via API
- Persistence across service restarts

### Improved Status Display
- Clear "Safe" or "Unsafe" status indicators
- Detailed threat level reporting
- Enhanced logging for all detection events

## Getting Started

### Prerequisites
- Node.js (v14+)
- TypeScript
- npm or yarn

### Installation

1. Install dependencies:
   ```bash
   npm install
   ```

2. Build the project:
   ```bash
   npm run build
   ```

3. Start the service:
   ```bash
   npm start
   ```

## Architecture

### Core Components

1. **Ipsum Feed Service**
   - Fetches and caches malicious IP data from the Ipsum repository
   - Manages local safe IP list
   - Performs IP reputation checks
   - Automatic refresh of malicious IP database

2. **Malicious Check Service**
   - Coordinates IP reputation checks
   - Manages safe IP list additions/removals
   - Provides composite threat analysis

3. **Packet Display Service**
   - Formats packet information for display
   - Enhances packet data with threat intelligence
   - Provides clean status indicators (Safe/Unsafe)

## API Reference

### Check Packet
Analyzes a network packet for potential threats.

```typescript
async checkPacket(packet: PacketData): Promise<MaliciousCheckResult>
```

### Add Safe IP
Adds an IP address to the safe list.

```typescript
async addSafeIp(ip: string): Promise<void>
```

### Remove Safe IP
Removes an IP address from the safe list.

```typescript
async removeSafeIp(ip: string): Promise<void>
```

### Format Packet Info
Formats packet information with threat status for display.

```typescript
formatPacketInfo(packet: PacketData, maliciousCheck: MaliciousCheckResult): string
```

## Data Flow

1. Packet data is received by the analysis service
2. Malicious check service examines the IP addresses
3. IPs are first checked against the safe list
4. If not in safe list, IPs are checked against the Ipsum database
5. Threat levels are calculated based on Ipsum scores
6. Packet display service formats the result with Safe/Unsafe status
7. Results are returned to the calling service

## Development

### Building
```bash
npm run build
```

### Testing
```bash
npm run test
```

### Running
```bash
npm run start