import { Suspense } from "react";
import { PacketTable } from "./components/packet-table";
import { RealTimeStatsWrapper } from "./components/real-time-stats-wrapper";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { AlertCircle, Cpu, Shield, Signal } from "lucide-react";
import { Badge } from "@/components/ui/badge";

export const dynamic = 'force-dynamic';
export const revalidate = 5;

export default function SnifferPage() {
  return (
    <div className="flex-1 space-y-4 p-4 md:p-8 pt-6">
      <div className="flex items-center justify-between space-y-2">
        <h2 className="text-3xl font-bold tracking-tight">Network Packet Sniffer</h2>
        <div className="flex items-center space-x-2">
          <Badge variant="outline" className="flex gap-1 px-3 py-1">
            <span className="h-2 w-2 rounded-full bg-green-500 animate-pulse"></span>
            Live Capture
          </Badge>
        </div>
      </div>
      
      <Tabs defaultValue="all" className="space-y-4">
        <div className="flex justify-between">
          <TabsList>
            <TabsTrigger value="all">All Packets</TabsTrigger>
            <TabsTrigger value="unsafe">Unsafe</TabsTrigger>
            <TabsTrigger value="safe">Safe</TabsTrigger>
          </TabsList>
        </div>
        
        <TabsContent value="all" className="space-y-4">
          <RealTimeStatsWrapper />
          
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center text-xl">
                <Signal className="mr-2 h-5 w-5" />
                Flowing Packets
              </CardTitle>
              <CardDescription>
                Real-time packet capture with threat analysis. Click any packet for detailed information.
              </CardDescription>
            </CardHeader>
            <CardContent className="px-0">
              <Suspense fallback={<div className="py-10 text-center">Loading packet data...</div>}>
                <PacketTable filter="all" />
              </Suspense>
            </CardContent>
          </Card>
        </TabsContent>
        
        <TabsContent value="unsafe" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            <Card className="bg-red-500/5 border-red-500/20">
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center text-lg text-red-500">
                  <AlertCircle className="mr-2 h-5 w-5" />
                  Unsafe Packets
                </CardTitle>
                <CardDescription>Packets flagged as unsafe by analysis</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">View all threats</div>
              </CardContent>
            </Card>
            <Card className="bg-amber-500/5 border-amber-500/20">
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center text-lg text-amber-500">
                  <Shield className="mr-2 h-5 w-5" />
                  DPI Analysis
                </CardTitle>
                <CardDescription>Deep Packet Inspection results</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">View findings</div>
              </CardContent>
            </Card>
            <Card className="bg-blue-500/5 border-blue-500/20">
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center text-lg text-blue-500">
                  <Cpu className="mr-2 h-5 w-5" />
                  Behavioral Analysis
                </CardTitle>
                <CardDescription>Network behavior anomalies</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">View anomalies</div>
              </CardContent>
            </Card>
          </div>
          
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center text-xl text-red-500">
                <AlertCircle className="mr-2 h-5 w-5" />
                Unsafe Packets
              </CardTitle>
              <CardDescription>
                Packets flagged as unsafe based on threat analysis
              </CardDescription>
            </CardHeader>
            <CardContent className="px-0">
              <Suspense fallback={<div className="py-10 text-center">Loading packet data...</div>}>
                <PacketTable filter="unsafe" />
              </Suspense>
            </CardContent>
          </Card>
        </TabsContent>
        
        <TabsContent value="safe" className="space-y-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center text-xl text-green-500">
                <Shield className="mr-2 h-5 w-5" />
                Safe Packets
              </CardTitle>
              <CardDescription>
                Packets verified as safe by threat analysis
              </CardDescription>
            </CardHeader>
            <CardContent className="px-0">
              <Suspense fallback={<div className="py-10 text-center">Loading packet data...</div>}>
                <PacketTable filter="safe" />
              </Suspense>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
} 