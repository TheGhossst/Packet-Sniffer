/**
 * Service for fetching and managing alerts
 */

// Types for alerts
export type AlertSeverity = 'high' | 'medium' | 'low' | 'info';
export type AlertStatus = 'active' | 'acknowledged' | 'resolved';
export type AlertType = 'security' | 'system' | 'performance';

export interface Alert {
  id: string;
  title: string;
  description: string;
  timestamp: string;
  severity: AlertSeverity;
  status: AlertStatus;
  type: AlertType;
  sourceIp?: string;
  sourcePort?: number;
  destinationIp?: string;
  destinationPort?: number;
  relatedMetric?: string;
}

export interface AlertsSummary {
  alerts: Alert[];
  totalCount: number;
  activeCount: number;
  securityCount: number;
  systemCount: number;
  performanceCount: number;
  highSeverityCount: number;
  lastUpdated: string;
}

// Mock data for development - will be replaced with actual API calls
const MOCK_ALERTS: Alert[] = [
  {
    id: '1',
    title: 'Potential malicious activity detected',
    description: 'Connection attempts from blacklisted IP: 185.143.223.47',
    timestamp: new Date(Date.now() - 2 * 60 * 1000).toISOString(), // 2 minutes ago
    severity: 'high',
    status: 'active',
    type: 'security',
    sourceIp: '185.143.223.47',
    destinationIp: '192.168.1.1',
    destinationPort: 443
  },
  {
    id: '2',
    title: 'High bandwidth usage detected',
    description: 'Unusual traffic pattern on port 443',
    timestamp: new Date(Date.now() - 10 * 60 * 1000).toISOString(), // 10 minutes ago
    severity: 'medium',
    status: 'active',
    type: 'performance',
    destinationPort: 443
  },
  {
    id: '3',
    title: 'Potential port scan detected',
    description: 'Multiple connection attempts from 192.168.1.45',
    timestamp: new Date(Date.now() - 35 * 60 * 1000).toISOString(), // 35 minutes ago
    severity: 'medium',
    status: 'active',
    type: 'security',
    sourceIp: '192.168.1.45'
  },
  {
    id: '4',
    title: 'Redis connection pool optimized',
    description: 'Performance improvement applied automatically',
    timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(), // 2 hours ago
    severity: 'info',
    status: 'resolved',
    type: 'system'
  },
  {
    id: '5',
    title: 'System maintenance completed',
    description: 'All services are back online and running normally',
    timestamp: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(), // Yesterday
    severity: 'info',
    status: 'resolved',
    type: 'system'
  },
  {
    id: '6',
    title: 'IPSUM feed updated',
    description: 'Downloaded latest blacklist data with 1,245 new entries',
    timestamp: new Date(Date.now() - 30 * 60 * 60 * 1000).toISOString(), // Yesterday morning
    severity: 'info',
    status: 'resolved',
    type: 'system'
  }
];

/**
 * Fetch alerts from the API
 */
export async function fetchAlerts(): Promise<AlertsSummary> {
  try {
    // TODO: Replace with actual API call when backend is ready
    // const response = await fetch('/api/alerts');
    // const data = await response.json();
    
    // For now, simulate API call with mock data
    await new Promise(resolve => setTimeout(resolve, 800)); // Simulate network delay
    
    const alerts = MOCK_ALERTS;
    const activeAlerts = alerts.filter(alert => alert.status === 'active');
    const securityAlerts = alerts.filter(alert => alert.type === 'security');
    const systemAlerts = alerts.filter(alert => alert.type === 'system');
    const performanceAlerts = alerts.filter(alert => alert.type === 'performance');
    const highSeverityAlerts = alerts.filter(alert => alert.severity === 'high');
    
    return {
      alerts,
      totalCount: alerts.length,
      activeCount: activeAlerts.length,
      securityCount: securityAlerts.length,
      systemCount: systemAlerts.length,
      performanceCount: performanceAlerts.length,
      highSeverityCount: highSeverityAlerts.length,
      lastUpdated: new Date().toISOString()
    };
  } catch (error) {
    console.error('Error fetching alerts:', error);
    return {
      alerts: [],
      totalCount: 0,
      activeCount: 0,
      securityCount: 0,
      systemCount: 0,
      performanceCount: 0,
      highSeverityCount: 0,
      lastUpdated: new Date().toISOString()
    };
  }
}

/**
 * Get relative time string (e.g., "2 minutes ago")
 */
export function getRelativeTimeString(timestamp: string): string {
  const date = new Date(timestamp);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffSec = Math.floor(diffMs / 1000);
  const diffMin = Math.floor(diffSec / 60);
  const diffHour = Math.floor(diffMin / 60);
  const diffDay = Math.floor(diffHour / 24);

  if (diffDay > 0) {
    return diffDay === 1 ? 'Yesterday' : `${diffDay} days ago`;
  }
  if (diffHour > 0) {
    return `${diffHour} ${diffHour === 1 ? 'hour' : 'hours'} ago`;
  }
  if (diffMin > 0) {
    return `${diffMin} ${diffMin === 1 ? 'minute' : 'minutes'} ago`;
  }
  return 'Just now';
}
