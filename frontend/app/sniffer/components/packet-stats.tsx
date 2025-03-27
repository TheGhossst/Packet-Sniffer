import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Shield, AlertCircle, ActivitySquare, ArrowDownUp } from "lucide-react";
import { getPackets } from "@/lib/packets";

async function getPacketStats() {
  const packets = await getPackets(100);
  
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
  
  return {
    totalPackets,
    safePackets,
    unsafePackets,
    unsafePercentage,
    protocols,
    topThreats
  };
}

export async function PacketStatsCards() {
  const stats = await getPacketStats();
  
  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">
            Total Packets
          </CardTitle>
          <ActivitySquare className="h-4 w-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{stats.totalPackets.toLocaleString()}</div>
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
          <div className="text-2xl font-bold text-green-500">{stats.safePackets.toLocaleString()}</div>
          <p className="text-xs text-muted-foreground">
            {Math.round((stats.safePackets / Math.max(stats.totalPackets, 1)) * 100)}% of total traffic
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
          <div className="text-2xl font-bold text-red-500">{stats.unsafePackets.toLocaleString()}</div>
          <p className="text-xs text-muted-foreground">
            {stats.unsafePercentage}% of total traffic
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
            {Object.entries(stats.protocols).slice(0, 3).map(([protocol, count]) => (
              <div key={protocol} className="flex items-center">
                <div className="w-16 font-medium">{protocol}</div>
                <div className="flex-1 mx-2">
                  <div className="h-2 rounded bg-secondary overflow-hidden">
                    <div 
                      className="h-full bg-primary" 
                      style={{ width: `${Math.round((count / stats.totalPackets) * 100)}%` }}
                    ></div>
                  </div>
                </div>
                <div className="w-10 text-xs text-muted-foreground text-right">
                  {Math.round((count / stats.totalPackets) * 100)}%
                </div>
              </div>
            ))}
          </div>
          {stats.topThreats.length > 0 && (
            <div className="mt-3 pt-3 border-t">
              <div className="text-xs font-medium mb-1">Top Threats:</div>
              {stats.topThreats.map((threat, i) => (
                <div key={i} className="text-xs text-muted-foreground">
                  {threat.type} ({threat.count})
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
} 