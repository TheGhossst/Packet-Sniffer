/**
 * Service for fetching service statuses
 */

export interface ServiceStatus {
  id: string;
  name: string;
  description: string;
  status: 'online' | 'offline' | 'degraded' | 'unknown';
  statusMessage: string;
  lastChecked: string;
}

export interface ServicesState {
  services: ServiceStatus[];
  lastUpdated: string;
}

/**
 * Fetch services status
 */
export async function fetchServicesStatus(): Promise<ServicesState> {
  try {
    // TODO: Replace with actual API call when backend is ready
    // const response = await fetch('/api/services/status');
    // const data = await response.json();
    
    // For now, simulate API call with mock data
    await new Promise(resolve => setTimeout(resolve, 600)); // Simulate network delay
    
    // Check if metrics endpoint is available by making a request
    let metricsStatus: 'online' | 'offline' = 'online';
    try {
      const response = await fetch('/api/metrics', { method: 'HEAD' });
      metricsStatus = response.ok ? 'online' : 'offline';
    } catch (error) {
      console.error('Error fetching metrics:', error);
      metricsStatus = 'offline';
    }
    
    const services: ServiceStatus[] = [
      {
        id: 'analysis-service',
        name: 'Analysis Service',
        description: 'Service health',
        status: 'online',
        statusMessage: 'Service is operating normally',
        lastChecked: new Date().toISOString(),
      },
      {
        id: 'ipsum-feed',
        name: 'IPSUM Feed',
        description: 'Blacklist feed status',
        status: 'online',
        statusMessage: 'Connected to feed and receiving updates',
        lastChecked: new Date().toISOString(),
      },
      {
        id: 'metrics-endpoint',
        name: 'Metrics Endpoint',
        description: 'Prometheus metrics',
        status: metricsStatus,
        statusMessage: metricsStatus === 'online' 
          ? 'Available and responding' 
          : 'Unable to connect to metrics endpoint',
        lastChecked: new Date().toISOString(),
      }
    ];
    
    return {
      services,
      lastUpdated: new Date().toISOString()
    };
  } catch (error) {
    console.error('Error fetching services status:', error);
    return {
      services: [],
      lastUpdated: new Date().toISOString()
    };
  }
}
