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

### Robust Error Handling
- Comprehensive error handling for API failures
- Detailed error logging with context
- Automatic fallback to default values when APIs fail
- Timeout management to prevent service delays
- Metrics tracking for API errors and timeouts

## Threat Intelligence

The analysis service now includes enhanced threat intelligence capabilities using multiple sources:

1. **Ipsum Feed** - Local blacklist of malicious IPs
2. **VirusTotal API** - Checks IP addresses against 70+ security vendors
3. **AbuseIPDB** - Community-driven database of reported abusive IP addresses

### Setup

To enable all threat intelligence features, you need to provide API keys for VirusTotal and AbuseIPDB:

1. Register for a free VirusTotal API key at [VirusTotal](https://www.virustotal.com/gui/join-us)
2. Register for a free AbuseIPDB API key at [AbuseIPDB](https://www.abuseipdb.com/register)
3. Create a `.env` file 

```bash
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=

REDIS_HOST=localhost
REDIS_PORT=6379 
```

## How It Works: Detailed Analysis Flow

The Analysis Service follows a sophisticated multi-stage evaluation process for each network packet, balancing thorough threat detection with performance optimization.

### 1. Packet Reception & Initial Processing

When a packet is received from the capture service (via Redis), the analysis pipeline begins:

1. **Packet Parsing**: The service extracts key attributes from the packet, focusing on IP addresses, ports, and protocol details
2. **Initial Metrics**: Basic packet statistics are recorded (size, type, etc.)
3. **Prioritization**: If the packet queue becomes too large, prioritization rules ensure critical traffic analysis

### 2. Safe IP Fast-Path

Before any expensive reputation checks, the service performs quick exclusion tests:

1. **Memory Cache Check**: First, the service checks an in-memory cache of recently verified safe IPs
   - This ultra-fast check allows immediate clearance of previously verified safe IPs
   - The cache automatically expires entries after 1 hour to ensure security

2. **Persistent Safe List Check**: If not in memory cache, checks against the persistent safe IP list
   - Safe IPs are stored persistently across service restarts
   - Manually trusted IPs and automatically learned safe IPs are included
   - If found, the packet is immediately marked "Safe" with zero threat score

### 3. Ipsum Feed Local Database Check

For IPs not in the safe list, a local database check occurs:

1. **Local Database Query**: The service queries the locally cached Ipsum feed data
   - This is a fast check as it uses an optimized in-memory data structure
   - No external API calls are made at this stage

2. **Decision Point**: Based on the Ipsum result, the service determines next steps:
   - If Ipsum flags the IP as malicious, proceed to external API verification
   - If Ipsum considers it clean, skip external APIs to conserve API usage

### 4. External API Verification (Smart Escalation)

Only when an IP is flagged as potentially malicious by Ipsum:

1. **Sequential API Checking**: The service doesn't call all APIs simultaneously
   - It starts with AbuseIPDB, which tends to respond more quickly
   - If AbuseIPDB confirms the IP is malicious (and Ipsum already flagged it), it may skip VirusTotal

2. **Timeout Management**: Each API call has built-in timeouts
   - 3-second timeout for initial response
   - 5-second hard timeout for the full request
   - If a timeout occurs, the service continues with available data

3. **Error Handling**: Robust error management ensures service stability
   - Network errors are gracefully handled
   - Rate limiting is respected to avoid API bans
   - Default "safe" values are used when APIs are unavailable

### 5. Intelligent Scoring System

After gathering data from available sources, a weighted scoring system calculates the threat level:

1. **Source Weighting**: Different sources have different reliability weights
   - Ipsum Feed: 40% weight
   - VirusTotal: 30% weight 
   - AbuseIPDB: 30% weight

2. **Multi-Factor Evaluation**: An IP is considered malicious if either:
   - The weighted score exceeds the threshold (3.0+)
   - Two or more independent sources flag it as malicious

3. **Threat Level Classification**:
   - 0-3: Low threat
   - 3-6: Medium threat
   - 6-10: High threat

### 6. Adaptive Safe IP Learning

The service employs a sophisticated system to automatically learn safe IPs:

1. **Frequency Tracking**: Non-malicious IPs are tracked across time
   - Each time a non-malicious IP is seen, its counter increments
   - After 5 occurrences without being flagged malicious, it's automatically added to the safe list
   - This adaptive system reduces future processing needs

2. **Automatic Cleanup**: The tracking system automatically cleans up stale entries
   - Entries older than 1 hour are removed to prevent memory leaks
   - Only legitimate, frequently seen IPs make it to the safe list

### 7. Result Formation & Enrichment

The final step creates a comprehensive result:

1. **Data Enrichment**: Additional context is added to the results when available
   - Country information
   - ISP details
   - Domain associations

2. **Reason Collection**: Clear explanations for the classification are compiled
   - Each source that flagged the IP contributes a reason
   - Detailed scores and detection counts are included

3. **Metrics Update**: Various metrics are updated for monitoring
   - Hit counters for each intelligence source
   - Processing times
   - Error rates

### 8. Performance Optimizations

Several optimizations ensure the service remains efficient:

1. **Deduplication**: Identical API requests are merged to avoid redundant calls
   - If multiple threads need the same IP check, only one API call is made

2. **Caching Strategy**: Results are cached with appropriate TTLs
   - Ipsum data refreshes every 24 hours
   - API results cache for 1 hour
   - Safe IPs cache indefinitely (unless removed)

3. **Prioritized Processing**: More dangerous traffic receives priority analysis
   - Known malicious IP ranges get deeper inspection
   - Historical pattern recognition guides resource allocation

### Weighted Scoring System

The service implements a weighted scoring system that combines results from all sources:

- Ipsum Feed: 40% weight
- VirusTotal: 30% weight
- AbuseIPDB: 30% weight

The combined score determines the threat level:
- 0-3: Low threat
- 3-6: Medium threat
- 6-10: High threat

IP addresses are also considered malicious if detected by 2 or more sources.

### Optimized API Usage

To minimize external API calls and respect rate limits, the service follows this approach:

1. First checks the local safe IP list (fastest check)
2. Then checks the Ipsum blacklist (local database)
3. **Only if an IP is flagged by Ipsum**, it checks with VirusTotal and AbuseIPDB for confirmation
4. This optimization significantly reduces API usage while maintaining detection capabilities

### Error Handling

The service implements a comprehensive error handling strategy for API interactions:

- **Graceful Degradation**: If any API fails, the service continues to function using available data sources
- **Detailed Error Logging**: Clear error messages with specific context for easier troubleshooting  
- **Timeout Management**: Automatically handles slow API responses to prevent service delays
- **Error Classification**: Different types of errors (timeouts, network issues, authentication) are identified and logged
- **Error Metrics**: Tracks and exposes error counts by source via Prometheus metrics

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| VIRUSTOTAL_API_KEY | API key for VirusTotal | "" |
| ABUSEIPDB_API_KEY | API key for AbuseIPDB | "" |
| REDIS_HOST | Redis host | "localhost" |
| REDIS_PORT | Redis port | 6379 |

### Troubleshooting API Integration

If your API dashboard shows 0 usage, check the following:

1. **API Keys Setup**
   - Ensure you've registered for API keys at [VirusTotal](https://www.virustotal.com/gui/join-us) and [AbuseIPDB](https://www.abuseipdb.com/register)
   - Create a `.env` file and add your actual API keys:
      ```bash
      VIRUSTOTAL_API_KEY=
      ABUSEIPDB_API_KEY=

      REDIS_HOST=localhost
      REDIS_PORT=6379 
      ```

2. **API Rate Limits**
   - VirusTotal free tier: 4 requests/minute, 500 requests/day
   - AbuseIPDB free tier: 1000 requests/day
   - The code includes built-in rate limiting to respect these limits

3. **Error Monitoring**
   - Check the service logs for API-related errors
   - Look for timeout warnings and connection issues
   - Monitor the API error metrics through the Prometheus endpoint

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
2. Start the service:
   ```bash
   npm run start
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

4. **Metrics Service**
   - Tracks and exposes performance metrics
   - Monitors API errors and timeouts
   - Provides Prometheus-compatible metrics endpoint

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

The analysis service follows a structured data flow for examining network packets:

```
                       ┌─────────────────┐
                       │                 │
                       │  Packet Data    │
                       │  from Redis     │
                       │                 │
                       └────────┬────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │  Malicious      │
                       │  Check Service  │
                       └────────┬────────┘
                                │
                                ▼
               ┌────────────────────────────────┐
               │     Is IP in Safe List?        │
               └───────────┬──────────┬─────────┘
                           │          │
                           │          │
                     Yes   │          │ No
                           │          │
                           ▼          ▼
┌──────────────────────┐         ┌────────────────────┐
│                      │         │                    │
│  Return Safe Result  │         │  Check Ipsum Feed  │
│                      │         │                    │
└──────────────────────┘         └─────────┬──────────┘
                                            │
                                            ▼
                                 ┌──────────────────────┐
                                 │  Is IP Malicious     │
                                 │  according to Ipsum? │
                                 └──────────┬───────────┘
                                            │
                          ┌─────────────────┴─────────────────┐
                          │                                   │
                          │                                   │
                    Yes   │                                   │  No
                          │                                   │
                          ▼                                   ▼
              ┌───────────────────────┐           ┌──────────────────────┐
              │ Check External APIs   │           │                      │
              │ (VirusTotal, AbuseIPDB)│          │ Skip External APIs   │
              └───────────┬───────────┘           └──────────┬───────────┘
                          │                                   │
                          │                                   │
                          ▼                                   │
              ┌───────────────────────┐                       │
              │ Calculate Threat Score│                       │
              │ & Determine Threat    │                       │
              │ Level                 │                       │
              └───────────┬───────────┘                       │
                          │                                   │
                          │                                   │
                          ▼                                   ▼
                       ┌─────────────────────────────────────────┐
                       │                                         │
                       │ Format Result & Update Metrics          │
                       │                                         │
                       └───────────────────┬─────────────────────┘
                                           │
                                           ▼
                       ┌─────────────────────────────────────────┐
                       │                                         │
                       │ Return Analysis Result                  │
                       │                                         │
                       └─────────────────────────────────────────┘
```

### Detailed Flow Steps

1. **Packet Ingestion**
   - Packet data is received from the capture service via Redis queue
   - The Analysis Service pulls packet data for processing

2. **Initial IP Check**
   - The destination IP address is extracted from the packet data
   - The IP is checked against the in-memory safe IP cache
   - If not found, it's checked against the persistent safe IP list

3. **Safe IP Fast Path**
   - If the IP is found in either safe list:
     - A "Safe" result is immediately returned
     - No further processing occurs, saving resources
     - The response includes a zero threat score and "safe" status

4. **Ipsum Feed Evaluation**
   - For IPs not in the safe list, the service checks the local Ipsum feed database
   - The Ipsum feed provides a simple score based on blacklist occurrences

5. **Conditional API Escalation**
   - If Ipsum flags the IP as potentially malicious:
     - External APIs are checked in sequence (AbuseIPDB first, then VirusTotal)
     - Early termination may occur if multiple sources confirm malicious status
   - If Ipsum considers the IP clean:
     - External APIs are skipped to conserve API quota
     - The IP is added to tracking for potential future safe-listing

6. **Comprehensive Score Calculation**
   - Results from all available sources are weighted and combined
   - A final threat score (0-10) is calculated
   - A threat level (low, medium, high) is determined

7. **Result Enrichment & Metrics**
   - Additional IP information is added (country, ISP, domain)
   - Detailed reasons for classification are compiled
   - Performance and detection metrics are updated

8. **Final Processing**
   - The packet display service formats the result
   - Clear "Safe" or "Unsafe" status is applied
   - The complete result is returned to the calling service

9. **Adaptive Learning**
   - Non-malicious IPs are tracked across multiple analyses
   - IPs that remain non-malicious over time are automatically added to the safe list
   - This creates a continuously improving system that gets faster over time

### Key Decision Points

- **Safe IP Check**: Immediate exit for trusted IPs
- **Ipsum Feed Check**: Determines whether to use external APIs
- **Multi-Source Confirmation**: An IP is malicious if either:
  - It scores above the threshold (≥3.0)
  - It's flagged by 2+ independent sources
- **API Timeout Management**: Service continues with available data if APIs timeout
- **Safe IP Learning**: IPs seen 5+ times without being flagged are auto-added to safe list

This structured flow ensures optimal performance while maintaining comprehensive threat detection capabilities.

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
```