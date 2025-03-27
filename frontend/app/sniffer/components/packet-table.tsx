"use client";

import { useState, useCallback, useEffect, startTransition } from "react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { AlertCircle, Clock, ExternalLink, Shield } from "lucide-react";
import Link from "next/link";
import { getPackets, Packet } from "@/lib/packets";
import { Button } from "@/components/ui/button";
import { formatDistanceToNow } from "date-fns";

function StatusBadge({ status }: { status: "Safe" | "Unsafe" }) {
  if (status === "Safe") {
    return (
      <Badge variant="outline" className="bg-green-500/10 text-green-500 border-green-500/20">
        <Shield className="mr-1 h-3 w-3" />
        Safe
      </Badge>
    );
  }
  
  return (
    <Badge variant="outline" className="bg-red-500/10 text-red-500 border-red-500/20">
      <AlertCircle className="mr-1 h-3 w-3" />
      Unsafe
    </Badge>
  );
}

function ThreatLevelBadge({ level }: { level: "trusted" | "low" | "medium" | "high" }) {
  const colors = {
    trusted: "bg-green-500/10 text-green-500 border-green-500/20",
    low: "bg-blue-500/10 text-blue-500 border-blue-500/20",
    medium: "bg-amber-500/10 text-amber-500 border-amber-500/20",
    high: "bg-red-500/10 text-red-500 border-red-500/20"
  };
  
  return (
    <Badge variant="outline" className={colors[level]}>
      {level.charAt(0).toUpperCase() + level.slice(1)}
    </Badge>
  );
}

export function PacketTable({ filter = "all" }: { filter?: "all" | "safe" | "unsafe" }) {
  const [packets, setPackets] = useState<Packet[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);
  
  const loadPackets = useCallback(async () => {
    try {
      setIsLoading(true);
      const data = await getPackets(50);
      
      const filteredData = filter === "all" 
        ? data 
        : filter === "safe" 
          ? data.filter(p => p.status === "Safe") 
          : data.filter(p => p.status === "Unsafe");
          
      startTransition(() => {
        setPackets(filteredData);
        setIsLoading(false);
      });
    } catch (error) {
      console.error("Failed to load packets:", error);
      setIsLoading(false);
    }
  }, [filter]);
  
  useEffect(() => {
    loadPackets();
    
    if (autoRefresh) {
      const interval = setInterval(() => {
        loadPackets();
      }, 20000); // Refresh every 20 seconds
      
      return () => clearInterval(interval);
    }
  }, [autoRefresh, loadPackets]);
  
  const toggleAutoRefresh = () => {
    setAutoRefresh(prev => !prev);
  };
  
  const handleRefresh = () => {
    loadPackets();
  };
  
  return (
    <div className="space-y-4">
      <div className="flex justify-between px-4">
        <div className="text-sm text-muted-foreground">
          Showing {packets.length} {filter !== "all" ? `${filter} ` : ""}packets
        </div>
        <div className="flex gap-2">
          <Button 
            variant="outline" 
            size="sm" 
            onClick={toggleAutoRefresh}
            className={autoRefresh ? "bg-green-500/10" : ""}
          >
            <Clock className="mr-2 h-4 w-4" />
            {autoRefresh ? "Auto-refresh on" : "Auto-refresh off"}
          </Button>
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={isLoading}>
            Refresh
          </Button>
        </div>
      </div>
      
      <ScrollArea className="h-[600px] rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[80px]">ID</TableHead>
              <TableHead className="w-[180px]">Timestamp</TableHead>
              <TableHead className="w-[150px]">Source IP</TableHead>
              <TableHead className="w-[150px]">Destination IP</TableHead>
              <TableHead className="w-[100px]">Protocol</TableHead>
              <TableHead className="w-[100px]">Status</TableHead>
              <TableHead className="w-[120px]">Threat Level</TableHead>
              <TableHead className="w-[80px]">Details</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {packets.length > 0 ? (
              packets.map((packet) => (
                <TableRow 
                  key={packet.id}
                  className={
                    packet.status === "Unsafe" 
                      ? "bg-red-500/5 hover:bg-red-500/10" 
                      : ""
                  }
                >
                  <TableCell className="font-medium">{packet.id}</TableCell>
                  <TableCell>
                    <div className="flex flex-col">
                      <span className="text-xs text-muted-foreground">
                        {(() => {
                          try {
                            // Handle both string timestamps and numeric timestamps
                            let date;
                            
                            if (typeof packet.timestamp === 'string') {
                              // For ISO strings or other date strings
                              if (packet.timestamp.match(/^\d+$/)) {
                                // If it's just a numeric string, treat as seconds
                                date = new Date(parseInt(packet.timestamp) * 1000);
                              } else {
                                date = new Date(packet.timestamp);
                              }
                            } else if (typeof packet.timestamp === 'number') {
                              // For numeric timestamps (assume seconds)
                              date = new Date(packet.timestamp * 1000);
                            } else {
                              return 'Invalid timestamp';
                            }
                            
                            // Check if date is valid before formatting
                            if (isNaN(date.getTime())) {
                              return 'Invalid timestamp';
                            }
                            
                            return formatDistanceToNow(date, { addSuffix: true });
                          } catch (error) {
                            console.error("Error formatting timestamp:", error);
                            return 'Invalid timestamp';
                          }
                        })()}
                      </span>
                      <span>
                        {(() => {
                          try {
                            // Handle both string timestamps and numeric timestamps
                            let date;
                            
                            if (typeof packet.timestamp === 'string') {
                              // For ISO strings or other date strings
                              if (packet.timestamp.match(/^\d+$/)) {
                                // If it's just a numeric string, treat as seconds
                                date = new Date(parseInt(packet.timestamp) * 1000);
                              } else {
                                date = new Date(packet.timestamp);
                              }
                            } else if (typeof packet.timestamp === 'number') {
                              // For numeric timestamps (assume seconds)
                              date = new Date(packet.timestamp * 1000);
                            } else {
                              return 'Invalid time';
                            }
                            
                            // Check if date is valid before formatting
                            if (isNaN(date.getTime())) {
                              return 'Invalid time';
                            }
                            
                            return date.toLocaleTimeString();
                          } catch (error) {
                            console.error("Error formatting time:", error);
                            return 'Invalid time';
                          }
                        })()}
                      </span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-col">
                      <span>{packet.src_ip}</span>
                      <span className="text-xs text-muted-foreground">Port: {packet.src_port}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-col">
                      <span>{packet.dst_ip}</span>
                      <span className="text-xs text-muted-foreground">Port: {packet.dst_port}</span>
                    </div>
                  </TableCell>
                  <TableCell>{packet.protocol}</TableCell>
                  <TableCell>
                    <StatusBadge status={packet.status} />
                  </TableCell>
                  <TableCell>
                    <ThreatLevelBadge level={packet.threat_level} />
                  </TableCell>
                  <TableCell>
                    <Link href={`/sniffer/packet/${packet.id}`}>
                      <Button variant="ghost" size="icon" className="h-8 w-8">
                        <ExternalLink className="h-4 w-4" />
                      </Button>
                    </Link>
                  </TableCell>
                </TableRow>
              ))
            ) : (
              <TableRow>
                <TableCell colSpan={8} className="h-24 text-center">
                  {isLoading ? "Loading packets..." : "No packets found"}
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </ScrollArea>
    </div>
  );
} 