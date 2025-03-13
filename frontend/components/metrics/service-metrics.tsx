'use client';

import { useEffect, useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { fetchMetrics, MetricsSummary } from '@/lib/metrics';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell, PieLabelRenderProps } from 'recharts';
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { cn } from '@/lib/utils';
import { Loader2 } from 'lucide-react';
import { Payload } from 'recharts/types/component/DefaultTooltipContent';

const REFRESH_INTERVAL = 10000; // 10 seconds

/**
 * Component for displaying service metrics in card format
 */
export function ServiceMetricsCards() {
  const [metrics, setMetrics] = useState<MetricsSummary | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const getMetrics = async () => {
      try {
        setLoading(true);
        const data = await fetchMetrics();
        setMetrics(data);
        setError(null);
      } catch (err) {
        console.error('Error fetching metrics:', err);
        setError('Failed to fetch metrics. Is the analysis service running?');
      } finally {
        setLoading(false);
      }
    };

    getMetrics();

    const intervalId = setInterval(getMetrics, REFRESH_INTERVAL);

    return () => clearInterval(intervalId);
  }, []);

  if (loading && !metrics) {
    return (
      <div className="flex justify-center items-center h-48">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
        <span className="ml-2 text-muted-foreground">Loading metrics...</span>
      </div>
    );
  }

  if (error && !metrics) {
    return (
      <Alert variant="destructive" className="mb-4">
        <AlertTitle>Error</AlertTitle>
        <AlertDescription>{error}</AlertDescription>
      </Alert>
    );
  }

  const data = metrics || {
    totalPacketsProcessed: 0,
    maliciousPacketsTotal: 0,
    processingErrors: 0,
    averageProcessingDuration: 0,
    safeListHits: 0,
    ipsumsBlacklistHits: 0,
    connectionStatus: 'disconnected' as const,
    lastUpdated: new Date().toISOString(),
    maliciousByThreatLevel: {
      high: 0,
      medium: 0,
      unknown: 0
    }
  };

  const lastUpdatedTime = new Date(data.lastUpdated).toLocaleTimeString();

  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <div className="flex flex-col space-y-1">
            <CardTitle>Total Packets</CardTitle>
            <CardDescription>Processed by analysis service</CardDescription>
          </div>
          <div className={cn(
            "ml-auto font-semibold",
            data.connectionStatus === 'connected' ? "text-green-500" : "text-red-500"
          )}>
            {data.connectionStatus === 'connected' ? "●" : "○"}
          </div>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{data.totalPacketsProcessed.toLocaleString()}</div>
          <p className="text-xs text-muted-foreground mt-2">
            Last updated: {lastUpdatedTime}
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <div className="flex flex-col space-y-1">
            <CardTitle>Malicious Packets</CardTitle>
            <CardDescription>Detected by analysis service</CardDescription>
          </div>
          <Badge variant={data.maliciousPacketsTotal > 0 ? "destructive" : "outline"}>
            {data.maliciousPacketsTotal > 0 ? "Alert" : "No Alerts"}
          </Badge>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{data.maliciousPacketsTotal.toLocaleString()}</div>
          <div className="flex justify-between mt-2">
            <Badge variant="outline" className="bg-red-500">High: {data.maliciousByThreatLevel.high}</Badge>
            <Badge variant="outline" className="bg-yellow-500">Medium: {data.maliciousByThreatLevel.medium}</Badge>
            <Badge variant="outline" className="bg-blue-500">Unknown: {data.maliciousByThreatLevel.unknown}</Badge>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <div className="flex flex-col space-y-1">
            <CardTitle>Processing Time</CardTitle>
            <CardDescription>Average per packet</CardDescription>
          </div>
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{data.averageProcessingDuration.toFixed(3)} s</div>
          <p className="text-xs text-muted-foreground mt-2">
            Errors: {data.processingErrors.toLocaleString()}
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <div className="flex flex-col space-y-1">
            <CardTitle>Detection Sources</CardTitle>
            <CardDescription>Source of malicious IP detection</CardDescription>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-2">
            <div className="flex flex-col">
              <span className="text-muted-foreground text-sm">IPSUM Blacklist</span>
              <span className="text-xl font-semibold">{data.ipsumsBlacklistHits.toLocaleString()}</span>
            </div>
            <div className="flex flex-col">
              <span className="text-muted-foreground text-sm">Safe IPs</span>
              <span className="text-xl font-semibold">{data.safeListHits.toLocaleString()}</span>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

interface CustomLabelProps extends PieLabelRenderProps {
  name: string;
  percent: number;
}

// Define the type for tooltip formatter using the Recharts Payload type
type TooltipFormatterCallback = (value: number, name?: string, entry?: Payload<number, string>, index?: number) => [string, string];

/**
 * Component for displaying service metrics in chart format
 */
export function ServiceMetricsCharts() {
  const [metrics, setMetrics] = useState<MetricsSummary | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<string>("threat");

  useEffect(() => {
    const getMetrics = async () => {
      try {
        setLoading(true);
        const data = await fetchMetrics();
        setMetrics(data);
        setError(null);
      } catch (err) {
        console.error('Error fetching metrics:', err);
        setError('Failed to fetch metrics from analysis service');
      } finally {
        setLoading(false);
      }
    };

    getMetrics();

    const intervalId = setInterval(getMetrics, REFRESH_INTERVAL);
    return () => clearInterval(intervalId);
  }, []);

  if (loading && !metrics) {
    return (
      <div className="flex justify-center items-center h-48">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
        <span className="ml-2 text-muted-foreground">Loading charts...</span>
      </div>
    );
  }

  if (error && !metrics) {
    return (
      <Alert variant="destructive">
        <AlertTitle>Error</AlertTitle>
        <AlertDescription>{error}</AlertDescription>
      </Alert>
    );
  }

  const threatLevelData = metrics ? [
    { name: 'High', value: metrics.maliciousByThreatLevel.high, fill: '#ef4444' },
    { name: 'Medium', value: metrics.maliciousByThreatLevel.medium, fill: '#f97316' },
    { name: 'Unknown', value: metrics.maliciousByThreatLevel.unknown, fill: '#3b82f6' }
  ].filter(item => item.value > 0) : [];

  const packetSizeData = metrics?.packetSizeDistribution || [];

  const detectionSourcesData = metrics ? [
    { name: 'Safe List', value: metrics.safeListHits, fill: '#22c55e' },
    { name: 'IPSUM Blacklist', value: metrics.ipsumsBlacklistHits, fill: '#f43f5e' }
  ].filter(item => item.value > 0) : [];

  const lastUpdatedTime = metrics
    ? new Date(metrics.lastUpdated).toLocaleTimeString()
    : new Date().toLocaleTimeString();

  const renderCustomizedPieLabel = ({ name, percent }: CustomLabelProps) => {
    return `${name}: ${(percent * 100).toFixed(0)}%`;
  };

  const tooltipFormatter: TooltipFormatterCallback = (value) => {
    return [`${value} packets`, 'Count'];
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-medium">Analysis Service Charts</h3>
        <p className="text-sm text-muted-foreground">
          Last updated: {lastUpdatedTime}
          {metrics?.connectionStatus === 'connected' ? (
            <span className="ml-2 text-green-500">●</span>
          ) : (
            <span className="ml-2 text-red-500">○</span>
          )}
        </p>
      </div>

      <Tabs defaultValue="threat" value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="threat">Threat Levels</TabsTrigger>
          <TabsTrigger value="size">Packet Sizes</TabsTrigger>
          <TabsTrigger value="detection">Detection Sources</TabsTrigger>
        </TabsList>

        <TabsContent value="threat" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>Malicious Packets by Threat Level</CardTitle>
              <CardDescription>
                Distribution of detected malicious packets by threat level
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="h-80">
                {threatLevelData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={threatLevelData}
                        cx="50%"
                        cy="50%"
                        labelLine={true}
                        label={renderCustomizedPieLabel}
                        outerRadius={80}
                        fill="#8884d8"
                        dataKey="value"
                      >
                        {threatLevelData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.fill} />
                        ))}
                      </Pie>
                      <Tooltip formatter={tooltipFormatter} />
                      <Legend />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex justify-center items-center h-full text-muted-foreground">
                    No malicious packets detected
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="size" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>Packet Size Distribution</CardTitle>
              <CardDescription>
                Distribution of packet sizes in bytes
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="h-80">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={packetSizeData}
                    margin={{
                      top: 5,
                      right: 30,
                      left: 20,
                      bottom: 5,
                    }}
                  >
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="bucket" />
                    <YAxis />
                    <Tooltip formatter={tooltipFormatter} />
                    <Legend />
                    <Bar dataKey="count" name="Packet Count" fill="#6366f1" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="detection" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>Detection Sources</CardTitle>
              <CardDescription>
                Distribution of packet classification sources
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="h-80">
                {detectionSourcesData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={detectionSourcesData}
                        cx="50%"
                        cy="50%"
                        labelLine={true}
                        label={renderCustomizedPieLabel}
                        outerRadius={80}
                        fill="#8884d8"
                        dataKey="value"
                      >
                        {detectionSourcesData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.fill} />
                        ))}
                      </Pie>
                      <Tooltip formatter={tooltipFormatter} />
                      <Legend />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex justify-center items-center h-full text-muted-foreground">
                    No detection data available
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}