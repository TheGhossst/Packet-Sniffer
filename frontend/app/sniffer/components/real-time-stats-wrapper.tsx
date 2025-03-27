"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Shield, AlertCircle, ActivitySquare, ArrowDownUp, Loader2, RefreshCw } from "lucide-react";
import { Packet } from "@/lib/packets";

const REFRESH_INTERVAL = 20000; // 20 seconds

export function RealTimeStatsWrapper() {
  const [stats, setStats] = useState<PacketStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());
  const [error, setError] = useState<string | null>(null);

  interface PacketStats {
    totalPackets: number;
    safePackets: number;
    unsafePackets: number;
    unsafePercentage: number;
    protocols: Record<string, number>;
    topThreats: Array<{ type: string; count: number }>;
  }

  const fetchStats = async () => {
    try {
      setLoading(true);
      const response = await fetch("/api/packets?limit=100", {
        cache: "no-store",
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch packets: ${response.status}`);
      }

      const packets: Packet[] = await response.json();
      
      const totalPackets = packets.length;
      const safePackets = packets.filter(p => p.status === "Safe").length;
      const unsafePackets = packets.filter(p => p.status === "Unsafe").length;
      
      const unsafePercentage = totalPackets > 0 
        ? Math.round((unsafePackets / totalPackets) * 100) 
        : 0;
      
      const protocols = packets.reduce((acc, packet) => {
        const protocol = packet.protocol;
        acc[protocol] = (acc[protocol] || 0) + 1;
        return acc;
      }, {} as Record<string, number>);
      
      const threatTypes = packets
        .filter(p => p.threat_details && p.threat_details.length > 0)
        .flatMap(p => p.threat_details!)
        .reduce((acc, threat) => {
          acc[threat.type] = (acc[threat.type] || 0) + 1;
          return acc;
        }, {} as Record<string, number>);
      
      const topThreats = Object.entries(threatTypes)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3)
        .map(([type, count]) => ({ type, count }));

      setStats({
        totalPackets,
        safePackets,
        unsafePackets,
        unsafePercentage,
        protocols,
        topThreats
      });
      
      setLastUpdated(new Date());
      setError(null);
    } catch (err) {
      console.error("Error fetching packet stats:", err);
      setError("Failed to fetch packet statistics");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();

    const intervalId = setInterval(fetchStats, REFRESH_INTERVAL);

    return () => clearInterval(intervalId);
  }, []);

  if (loading && !stats) {
    return (
      <div className="flex justify-center items-center h-48">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
        <span className="ml-2 text-muted-foreground">Loading statistics...</span>
      </div>
    );
  }

  if (error && !stats) {
    return (
      <div className="p-4 border border-red-200 rounded-md bg-red-50 text-red-800">
        <div className="flex items-center">
          <AlertCircle className="h-5 w-5 mr-2" />
          <div>
            <p className="font-medium">Error loading statistics</p>
            <p className="text-sm">{error}</p>
          </div>
        </div>
      </div>
    );
  }
  
  const data = stats || {
    totalPackets: 0,
    safePackets: 0,
    unsafePackets: 0,
    unsafePercentage: 0,
    protocols: {},
    topThreats: []
  };

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h2 className="text-xl font-bold">Real-Time Network Statistics</h2>
        <div className="flex items-center text-xs text-muted-foreground">
          <RefreshCw className="h-3 w-3 mr-1" />
          Last updated: {lastUpdated.toLocaleTimeString()}
        </div>
      </div>
      
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Total Packets
            </CardTitle>
            <ActivitySquare className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{data.totalPackets.toLocaleString()}</div>
            <p className="text-xs text-muted-foreground">
              Analyzed in real-time
            </p>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Safe Packets
            </CardTitle>
            <Shield className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-500">{data.safePackets.toLocaleString()}</div>
            <p className="text-xs text-muted-foreground">
              {Math.round((data.safePackets / Math.max(data.totalPackets, 1)) * 100)}% of total traffic
            </p>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Unsafe Packets
            </CardTitle>
            <AlertCircle className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-500">{data.unsafePackets.toLocaleString()}</div>
            <p className="text-xs text-muted-foreground">
              {data.unsafePercentage}% of total traffic
            </p>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Protocol Distribution
            </CardTitle>
            <ArrowDownUp className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {Object.entries(data.protocols).slice(0, 3).map(([protocol, count]) => (
                <div key={protocol} className="flex items-center">
                  <div className="w-16 font-medium">{protocol}</div>
                  <div className="flex-1 mx-2">
                    <div className="h-2 rounded bg-secondary overflow-hidden">
                      <div 
                        className="h-full bg-primary" 
                        style={{ width: `${Math.round((count / data.totalPackets) * 100)}%` }}
                      ></div>
                    </div>
                  </div>
                  <div className="w-10 text-xs text-muted-foreground text-right">
                    {Math.round((count / data.totalPackets) * 100)}%
                  </div>
                </div>
              ))}
            </div>
            {data.topThreats.length > 0 && (
              <div className="mt-3 pt-3 border-t">
                <div className="text-xs font-medium mb-1">Top Threats:</div>
                {data.topThreats.map((threat, i) => (
                  <div key={i} className="text-xs text-muted-foreground">
                    {threat.type} ({threat.count})
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
} 