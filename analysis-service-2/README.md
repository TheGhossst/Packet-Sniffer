# Analysis Service 2.0

An enhanced network traffic analysis service with improved threat intelligence capabilities for the Network IDS.

## Features

### Core Functionality
- Real-time packet analysis and threat detection
- Comprehensive IP reputation checking
- Configurable threat level identification
- Detailed packet information formatting

### Deep Packet Inspection (DPI)
- **Payload Analysis**: Examine packet payloads rather than just metadata
- **Protocol-Specific Analysis**:
  - **HTTP Analysis**: Detect suspicious URLs, user agents, and web attacks
  - **DNS Analysis**: Identify suspicious domains and DNS tunneling attempts
  - **TLS/HTTPS Analysis**: Detect malicious clients via TLS fingerprinting
  - **SMTP/Email Analysis**: Identify phishing attempts and suspicious attachments
  - **SMB/Windows Analysis**: Detect lateral movement and exploitation attempts
  - **ICMP Analysis**: Identify ping sweeps and covert channel communications
- **Pattern Matching**: Identify common attack patterns like SQL injection and XSS

### Behavioral Analysis
- **Connection Tracking**: Monitor connections between hosts over time
- **Traffic Pattern Analysis**: Detect anomalies in network traffic patterns
- **Anomaly Detection**:
  - Port scanning detection
  - High traffic volume alerts
  - Excessive connection monitoring
  - Unusual port usage tracking

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
- Display of DPI and behavioral analysis findings

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
4. **Deep Packet Inspection** - Analyzes packet contents for malicious patterns
5. **Behavioral Analysis** - Monitors network behavior for suspicious patterns

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

### 2. Deep Packet Inspection

For packets containing payload data:

1. **Payload Decoding**: Base64-encoded payloads are decoded for analysis
2. **Protocol Detection**: The packet is classified based on protocol and port information
3. **Protocol-Specific Analysis**:
   - **HTTP Analysis**: Examines web traffic for suspicious patterns, malicious URLs, and web attacks
   - **DNS Analysis**: Detects suspicious domain requests, DNS tunneling, and domain generation algorithms
   - **TLS/HTTPS Analysis**: Identifies malicious clients through TLS fingerprinting and cipher suite analysis
   - **SMTP/Email Analysis**: Detects phishing attempts, suspicious attachments, and email spoofing
   - **SMB/Windows Analysis**: Identifies lateral movement, exploitation attempts, and administrative share access
   - **ICMP Analysis**: Detects ping sweeps, ICMP tunneling, and covert channels
4. **Pattern Matching**: Generic pattern matching for common attacks like SQL injection and XSS

### 3. Behavioral Analysis

The service maintains state across multiple packets to detect behavioral patterns:

1. **Connection Tracking**: Monitors connections between source/destination pairs
2. **Traffic Pattern Analysis**: Identifies anomalies in communication patterns
3. **Anomaly Detection**:
   - **Port Scanning**: Detects attempts to scan multiple ports on a target
   - **Traffic Volume**: Alerts on unusually high traffic from a source
   - **Connection Diversity**: Identifies sources connecting to many different destinations
   - **Protocol Anomalies**: Detects unusual protocol usage patterns

### 4. Safe IP Fast-Path

Before any expensive reputation checks, the service performs quick exclusion tests:

1. **Memory Cache Check**: First, the service checks an in-memory cache of recently verified safe IPs
   - This ultra-fast check allows immediate clearance of previously verified safe IPs
   - The cache automatically expires entries after 1 hour to ensure security

2. **Persistent Safe List Check**: If not in memory cache, checks against the persistent safe IP list
   - Safe IPs are stored persistently across service restarts
   - Manually trusted IPs and automatically learned safe IPs are included
   - If found, the packet is immediately marked "Safe" with zero threat score

### 5. Ipsum Feed Local Database Check

For IPs not in the safe list, a local database check occurs:

1. **Local Database Query**: The service queries the locally cached Ipsum feed data
   - This is a fast check as it uses an optimized in-memory data structure
   - No external API calls are made at this stage

2. **Decision Point**: Based on the Ipsum result, the service determines next steps:
   - If Ipsum flags the IP as malicious, proceed to external API verification
   - If Ipsum considers it clean, skip external APIs to conserve API usage

### 6. External API Verification (Smart Escalation)

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

### 7. Combined Threat Assessment

Results from all analysis methods are combined:

1. **IP Reputation**: Results from Ipsum, VirusTotal, and AbuseIPDB
2. **DPI Findings**: Protocol-specific suspicious patterns
3. **Behavioral Anomalies**: Suspicious traffic patterns

### 8. Intelligent Scoring System

After gathering data from available sources, a weighted scoring system calculates the threat level:

1. **Source Weighting**: Different sources have different reliability weights
   - Ipsum Feed: 40% weight
   - VirusTotal: 30% weight 
   - AbuseIPDB: 30% weight
   - DPI findings can override with high confidence detections
   - Behavioral anomalies can escalate the threat level

2. **Multi-Factor Evaluation**: An IP is considered malicious if either:
   - The weighted score exceeds the threshold (3.0+)
   - Two or more independent sources flag it as malicious
   - DPI identifies high-severity malicious patterns
   - Behavioral analysis detects clear attack patterns

3. **Threat Level Classification**:
   - 0-3: Low threat
   - 3-6: Medium threat
   - 6-10: High threat

### 9. Adaptive Safe IP Learning

The service employs a sophisticated system to automatically learn safe IPs:

1. **Frequency Tracking**: Non-malicious IPs are tracked across time
   - Each time a non-malicious IP is seen, its counter increments
   - After 5 occurrences without being flagged malicious, it's automatically added to the safe list
   - This adaptive system reduces future processing needs

2. **Automatic Cleanup**: The tracking system automatically cleans up stale entries
   - Entries older than 1 hour are removed to prevent memory leaks
   - Only legitimate, frequently seen IPs make it to the safe list

### 10. Result Formation & Enrichment

The final step creates a comprehensive result:

1. **Data Enrichment**: Additional context is added to the results when available
   - Country information
   - ISP details
   - Domain associations
   - Protocol-specific findings
   - Behavioral analysis details

2. **Reason Collection**: Clear explanations for the classification are compiled
   - Each source that flagged the IP contributes a reason
   - Detailed scores and detection counts are included
   - DPI and behavioral findings are listed

3. **Metrics Update**: Various metrics are updated for monitoring
   - Hit counters for each intelligence source
   - Processing times
   - Error rates
   - DPI detection counts
   - Behavioral anomaly metrics

### 11. Performance Optimizations

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
   - Integrates DPI and behavioral analysis results

3. **DPI Service**
   - Analyzes packet payloads for suspicious patterns
   - Performs protocol-specific analysis (HTTP, DNS, TLS, SMTP, SMB, ICMP)
   - Identifies common attack patterns (SQL injection, XSS)
   - Provides confidence scores for findings

4. **Behavioral Analysis Service**
   - Tracks connections between hosts over time
   - Monitors traffic patterns and identifies anomalies
   - Detects attacks that span multiple packets (port scans, DoS)
   - Maintains connection state information

5. **Packet Display Service**
   - Formats packet information for display
   - Enhances packet data with threat intelligence, DPI and behavioral findings
   - Provides clean status indicators (Safe/Unsafe)

6. **Metrics Service**
   - Tracks and exposes performance metrics
   - Monitors API errors and timeouts
   - Counts DPI and behavioral detections
   - Provides Prometheus-compatible metrics endpoint

## Testing

The analysis service includes comprehensive test suites:

```bash
# Run basic IP reputation tests
npm run test

# Run enhanced features tests (DPI, Behavioral Analysis)
npm run test:enhanced
```

## Development

### Building
```bash
npm run build
```

### Testing
```bash
npm run test
npm run test:enhanced  # For testing DPI and behavioral analysis
```

### Running
```bash
npm run start
```