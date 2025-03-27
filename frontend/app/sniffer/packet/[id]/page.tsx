import { Suspense } from "react";
import Link from "next/link";
import { notFound } from "next/navigation";
import { getPacketById } from "@/lib/packets";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { 
  AlertCircle, ArrowLeft, Clock, Database, Eye, 
  Network, Server, Shield, Info, HardDrive, Layers 
} from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";

export const dynamic = 'force-dynamic';
export const revalidate = 20;

function isPrivateIp(ip: string): boolean {
  return ip.startsWith('192.168.') || 
         ip.startsWith('10.') || 
         ip.startsWith('172.16.') || 
         ip.startsWith('172.17.') || 
         ip.startsWith('172.18.') || 
         ip.startsWith('172.19.') || 
         ip.startsWith('172.20.') || 
         ip.startsWith('172.21.') || 
         ip.startsWith('172.22.') || 
         ip.startsWith('172.23.') || 
         ip.startsWith('172.24.') || 
         ip.startsWith('172.25.') || 
         ip.startsWith('172.26.') || 
         ip.startsWith('172.27.') || 
         ip.startsWith('172.28.') || 
         ip.startsWith('172.29.') || 
         ip.startsWith('172.30.') || 
         ip.startsWith('172.31.');
}

function getPortService(port: number): string {
  const commonPorts: Record<number, string> = {
    20: 'FTP Data',
    21: 'FTP Control',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    465: 'SMTPS',
    587: 'SMTP Submission',
    993: 'IMAPS',
    995: 'POP3S',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    8080: 'HTTP Alternate'
  };
  
  return commonPorts[port] || 'Unknown';
}

async function PacketDetails({ id }: { id: string }) {
  const packet = await getPacketById(id);
  
  if (!packet) {
    notFound();
  }
  
  const timestamp = new Date(packet.timestamp);
  const formattedDate = timestamp.toLocaleDateString();
  const formattedTime = timestamp.toLocaleTimeString();
  
  const getStatusClass = (status: "Safe" | "Unsafe") => {
    return status === "Safe" 
      ? "bg-green-500/10 text-green-500 border-green-500/20" 
      : "bg-red-500/10 text-red-500 border-red-500/20";
  };
  
  const getThreatLevelClass = (level: "trusted" | "low" | "medium" | "high") => {
    const classes = {
      trusted: "bg-green-500/10 text-green-500 border-green-500/20",
      low: "bg-blue-500/10 text-blue-500 border-blue-500/20",
      medium: "bg-amber-500/10 text-amber-500 border-amber-500/20",
      high: "bg-red-500/10 text-red-500 border-red-500/20"
    };
    return classes[level];
  };
  
  const statusClass = getStatusClass(packet.status);
  const threatLevelClass = getThreatLevelClass(packet.threat_level);
  
  const isSourcePrivate = isPrivateIp(packet.src_ip);
  const isDestPrivate = isPrivateIp(packet.dst_ip);
  
  const srcPortService = getPortService(packet.src_port);
  const dstPortService = getPortService(packet.dst_port);
  
  return (
    <div className="space-y-6">
      <div className="flex flex-col space-y-3 lg:flex-row lg:items-center lg:justify-between lg:space-y-0">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Packet Details: {id}</h2>
          <p className="text-muted-foreground">
            Detailed analysis results for packet {id}
          </p>
        </div>
        
        <div className="flex flex-col gap-2 sm:flex-row sm:gap-4">
          <Link href="/sniffer">
            <Button variant="outline">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to Sniffer
            </Button>
          </Link>
        </div>
      </div>
      
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Layers className="mr-2 h-5 w-5" />
            Packet Overview
          </CardTitle>
          <CardDescription>Basic information about the packet</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-6">
          <div className="grid gap-3 md:grid-cols-4">
            <div className="flex flex-col space-y-1.5">
              <div className="text-sm font-medium text-muted-foreground">Status</div>
              <Badge variant="outline" className={cn("w-fit py-1 px-2", statusClass)}>
                {packet.status === "Safe" ? (
                  <Shield className="mr-1 h-3 w-3" />
                ) : (
                  <AlertCircle className="mr-1 h-3 w-3" />
                )}
                {packet.status}
              </Badge>
            </div>
            <div className="flex flex-col space-y-1.5">
              <div className="text-sm font-medium text-muted-foreground">Threat Level</div>
              <Badge variant="outline" className={cn("w-fit py-1 px-2", threatLevelClass)}>
                {packet.threat_level.charAt(0).toUpperCase() + packet.threat_level.slice(1)}
              </Badge>
            </div>
            <div className="flex flex-col space-y-1.5">
              <div className="text-sm font-medium text-muted-foreground">Protocol</div>
              <div className="font-semibold">{packet.protocol}</div>
            </div>
            <div className="flex flex-col space-y-1.5">
              <div className="text-sm font-medium text-muted-foreground">Packet Size</div>
              <div className="font-semibold">{packet.packet_size} bytes</div>
            </div>
          </div>
          
          <div className="border-t pt-4">
            <h3 className="text-lg font-semibold mb-3">Connection Details</h3>
            <div className="grid md:grid-cols-2 gap-6">
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-md flex items-center">
                    <HardDrive className="mr-2 h-4 w-4" />
                    Source
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  <div className="flex justify-between">
                    <span className="text-sm text-muted-foreground">IP Address:</span>
                    <span className="font-medium">{packet.src_ip}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-muted-foreground">IP Type:</span>
                    <Badge variant="outline" className={isSourcePrivate ? "bg-blue-500/10" : "bg-amber-500/10"}>
                      {isSourcePrivate ? "Private" : "Public"}
                    </Badge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-muted-foreground">Port:</span>
                    <span className="font-medium">{packet.src_port}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-muted-foreground">Service:</span>
                    <span>{srcPortService}</span>
                  </div>
                </CardContent>
              </Card>
              
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-md flex items-center">
                    <Server className="mr-2 h-4 w-4" />
                    Destination
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  <div className="flex justify-between">
                    <span className="text-sm text-muted-foreground">IP Address:</span>
                    <span className="font-medium">{packet.dst_ip}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-muted-foreground">IP Type:</span>
                    <Badge variant="outline" className={isDestPrivate ? "bg-blue-500/10" : "bg-amber-500/10"}>
                      {isDestPrivate ? "Private" : "Public"}
                    </Badge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-muted-foreground">Port:</span>
                    <span className="font-medium">{packet.dst_port}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-muted-foreground">Service:</span>
                    <span>{dstPortService}</span>
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>
          
          <div className="grid gap-3 md:grid-cols-2 border-t pt-4">
            <div className="flex flex-col space-y-1.5">
              <div className="text-sm font-medium text-muted-foreground">Timestamp</div>
              <div className="font-semibold flex items-center">
                <Clock className="mr-1 h-3 w-3" />
                {formattedDate} {formattedTime}
              </div>
            </div>
            
            {packet.timestamp_start && packet.timestamp_end && (
              <div className="flex flex-col space-y-1.5">
                <div className="text-sm font-medium text-muted-foreground">Duration</div>
                <div className="font-semibold">
                  {((packet.timestamp_end - packet.timestamp_start) / 1000).toFixed(3)} seconds
                </div>
              </div>
            )}
          </div>
          
          {(isSourcePrivate || isDestPrivate) && (
            <div className="border-t pt-4">
              <Card className="bg-blue-500/5 border-blue-500/20">
                <CardHeader className="pb-2">
                  <CardTitle className="flex items-center text-blue-600">
                    <Info className="mr-2 h-4 w-4" />
                    Private Network Traffic Assessment
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-sm mb-2">
                    This packet contains traffic {isSourcePrivate && isDestPrivate ? 
                      "between private IP addresses" : 
                      isSourcePrivate ? 
                        "from a private IP address to " + (isDestPrivate ? "another private IP" : "a public IP") : 
                        "from a public IP to a private IP"}.
                  </p>
                  <p className="text-sm text-muted-foreground">
                    {packet.status === "Safe" ? 
                      "Private IP traffic is generally considered safe unless DPI or behavioral analysis indicates suspicious patterns." : 
                      "While this packet involves private IP addresses, it has been flagged due to suspicious payload patterns or behavioral anomalies."}
                  </p>
                </CardContent>
              </Card>
            </div>
          )}
        </CardContent>
      </Card>
      
      <Tabs defaultValue="threat" className="w-full">
        <TabsList className="w-full grid grid-cols-4">
          <TabsTrigger value="threat">Threat Analysis</TabsTrigger>
          <TabsTrigger value="dpi">DPI Results</TabsTrigger>
          <TabsTrigger value="behavioral">Behavioral Analysis</TabsTrigger>
          <TabsTrigger value="payload">Raw Payload</TabsTrigger>
        </TabsList>
        
        <TabsContent value="threat" className="w-full">
          <Card className="w-full">
            <CardHeader>
              <CardTitle className="flex items-center">
                <Shield className="mr-2 h-5 w-5" />
                Threat Analysis Results
              </CardTitle>
              <CardDescription>
                Overall threat assessment for this packet
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 md:grid-cols-2">
                <Card className={cn(statusClass, "bg-opacity-5 border-opacity-20")}>
                  <CardHeader className="pb-2">
                    <CardTitle className={cn("text-lg", packet.status === "Safe" ? "text-green-500" : "text-red-500")}>
                      Status: {packet.status}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm text-muted-foreground">
                      {packet.status === "Safe" 
                        ? "This packet has been analyzed and does not contain known threats."
                        : "This packet has been flagged as potentially malicious."}
                    </p>
                  </CardContent>
                </Card>
                
                <Card className={cn(threatLevelClass, "bg-opacity-5 border-opacity-20")}>
                  <CardHeader className="pb-2">
                    <CardTitle className={cn("text-lg", 
                      packet.threat_level === "trusted" ? "text-green-500" : 
                      packet.threat_level === "low" ? "text-blue-500" : 
                      packet.threat_level === "medium" ? "text-amber-500" : 
                      "text-red-500"
                    )}>
                      Threat Level: {packet.threat_level.charAt(0).toUpperCase() + packet.threat_level.slice(1)}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm text-muted-foreground">
                      {packet.threat_level === "trusted" && "Packet is trusted with no indicators of compromise."}
                      {packet.threat_level === "low" && "Packet has a low threat level with minimal suspicious indicators."}
                      {packet.threat_level === "medium" && "Packet has a moderate threat level with some suspicious patterns."}
                      {packet.threat_level === "high" && "Packet has a high threat level with strong indicators of malicious activity."}
                    </p>
                  </CardContent>
                </Card>
              </div>
              
              {packet.threat_details && packet.threat_details.length > 0 ? (
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-lg">Threat Details</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="grid md:grid-cols-3 gap-4 mb-4">
                      <div className="space-y-2">
                        <div className="text-sm font-medium">Risk Score</div>
                        <div className={cn(
                          "text-2xl font-bold rounded-md px-3 py-1 w-fit",
                          packet.threat_level === "trusted" ? "bg-green-500/10 text-green-600" :
                          packet.threat_level === "low" ? "bg-blue-500/10 text-blue-600" :
                          packet.threat_level === "medium" ? "bg-amber-500/10 text-amber-600" :
                          "bg-red-500/10 text-red-600"
                        )}>
                          {packet.threat_level === "trusted" ? "0-20" :
                           packet.threat_level === "low" ? "21-40" :
                           packet.threat_level === "medium" ? "41-70" :
                           "71-100"}
                        </div>
                      </div>
                      
                      <div className="space-y-2">
                        <div className="text-sm font-medium">Detection Method</div>
                        <div className="font-semibold">
                          {packet.dpi_results?.isSuspicious ? "Deep Packet Inspection + " : ""}
                          {packet.behavioral_results?.anomalies?.length ? "Behavioral Analysis + " : ""}
                          Signature-Based Detection
                        </div>
                      </div>
                      
                      <div className="space-y-2">
                        <div className="text-sm font-medium">First Detected</div>
                        <div className="font-semibold">{formattedDate} {formattedTime}</div>
                      </div>
                    </div>
                    
                    <ScrollArea className="h-[300px] rounded-md">
                      <div className="space-y-4">
                        {packet.threat_details.map((threat, index) => (
                          <div key={index} className="border p-4 rounded-md">
                            <div className="flex justify-between items-start mb-3">
                              <h4 className="font-medium text-lg">{threat.type}</h4>
                              <Badge variant="outline" className={cn(getThreatLevelClass(threat.severity))}>
                                Severity: {threat.severity}
                              </Badge>
                            </div>
                            <p className="text-sm text-muted-foreground mb-3">{threat.description}</p>
                            
                            <div className="grid md:grid-cols-2 gap-4 mt-3">
                              <div>
                                <h5 className="text-sm font-medium mb-2">Potential Impact</h5>
                                <p className="text-sm text-muted-foreground">
                                  {threat.severity === "high" ? 
                                    "May lead to data breach, system compromise, or service disruption." :
                                    threat.severity === "medium" ?
                                    "Could expose sensitive information or allow unauthorized access." :
                                    "Minimal impact, but indicates suspicious activity."}
                                </p>
                              </div>
                              
                              <div>
                                <h5 className="text-sm font-medium mb-2">Recommended Action</h5>
                                <p className="text-sm text-muted-foreground">
                                  {threat.severity === "high" ? 
                                    "Block this traffic immediately and investigate source/destination for compromise." :
                                    threat.severity === "medium" ?
                                    "Monitor this connection closely and consider blocking if activity increases." :
                                    "Review traffic patterns to ensure this is expected communication."}
                                </p>
                              </div>
                            </div>
                            
                            {threat.confidence && (
                              <div className="mt-3 pt-3 border-t">
                                <div className="flex justify-between items-center">
                                  <div className="text-sm font-medium">Detection Confidence</div>
                                  <Badge variant="outline">
                                    {Math.round(threat.confidence * 100)}%
                                  </Badge>
                                </div>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </ScrollArea>
                    
                    <div className="mt-4 pt-4 border-t">
                      <h4 className="font-medium mb-2">Mitigation Suggestions</h4>
                      <ul className="space-y-2 text-sm text-muted-foreground">
                        <li className="flex items-start">
                          <span className="bg-blue-500/20 text-blue-500 rounded-full h-5 w-5 flex items-center justify-center mr-2 mt-0.5">1</span>
                          <span>Update firewall rules to block traffic from detected malicious sources</span>
                        </li>
                        <li className="flex items-start">
                          <span className="bg-blue-500/20 text-blue-500 rounded-full h-5 w-5 flex items-center justify-center mr-2 mt-0.5">2</span>
                          <span>Investigate connected systems for signs of compromise</span>
                        </li>
                        <li className="flex items-start">
                          <span className="bg-blue-500/20 text-blue-500 rounded-full h-5 w-5 flex items-center justify-center mr-2 mt-0.5">3</span>
                          <span>Apply latest security patches to affected systems</span>
                        </li>
                      </ul>
                    </div>
                  </CardContent>
                </Card>
              ) : (
                <div className="text-center py-8 text-muted-foreground">
                  <Shield className="mx-auto h-12 w-12 opacity-20 mb-2" />
                  <p>No specific threat details available for this packet</p>
                  <p className="text-sm mt-2">This packet has been analyzed and no known threats were detected</p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
        
        <TabsContent value="dpi" className="w-full">
          <Card className="w-full">
            <CardHeader>
              <CardTitle className="flex items-center">
                <Database className="mr-2 h-5 w-5" />
                Deep Packet Inspection Results
              </CardTitle>
              <CardDescription>
                Results from analyzing the packet payload
              </CardDescription>
            </CardHeader>
            <CardContent>
              {packet.dpi_results ? (
                <div className="space-y-4">
                  <div className="grid gap-4 md:grid-cols-3">
                    <Card>
                      <CardHeader className="pb-2">
                        <CardTitle className="text-sm font-medium">Protocol Analysis</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="text-2xl font-bold">{packet.dpi_results.protocol || packet.protocol}</div>
                        <p className="text-xs text-muted-foreground mt-1">
                          {packet.dpi_results.protocol ? "Detected protocol from payload inspection" : "Transport protocol"}
                        </p>
                      </CardContent>
                    </Card>
                    
                    <Card>
                      <CardHeader className="pb-2">
                        <CardTitle className="text-sm font-medium">Suspicion Level</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className={cn("text-2xl font-bold", packet.dpi_results.isSuspicious ? "text-red-500" : "text-green-500")}>
                          {packet.dpi_results.isSuspicious ? "Suspicious" : "Normal"}
                        </div>
                        <p className="text-xs text-muted-foreground mt-1">
                          {packet.dpi_results.isSuspicious 
                            ? "Abnormal patterns detected in packet content" 
                            : "No suspicious patterns detected"}
                        </p>
                      </CardContent>
                    </Card>
                    
                    <Card>
                      <CardHeader className="pb-2">
                        <CardTitle className="text-sm font-medium">Analysis Confidence</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="text-2xl font-bold">
                          {packet.dpi_results.confidence ? `${Math.round(packet.dpi_results.confidence * 100)}%` : "N/A"}
                        </div>
                        <p className="text-xs text-muted-foreground mt-1">
                          {packet.dpi_results.confidence && packet.dpi_results.confidence > 0.8 
                            ? "High confidence in analysis results" 
                            : packet.dpi_results.confidence && packet.dpi_results.confidence > 0.5
                            ? "Medium confidence in analysis results"
                            : "Low confidence or insufficient data"}
                        </p>
                      </CardContent>
                    </Card>
                  </div>

                  <Card className="bg-slate-50 dark:bg-slate-900">
                    <CardHeader className="pb-2">
                      <CardTitle className="text-md flex items-center">
                        <Database className="mr-2 h-4 w-4" />
                        Protocol Insights
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-2">
                      <div className="grid md:grid-cols-2 gap-4">
                        <div>
                          <h4 className="text-sm font-medium mb-2">Protocol Details</h4>
                          <div className="text-sm space-y-1">
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">Protocol Family:</span>
                              <span>{packet.protocol === "TCP" || packet.protocol === "UDP" ? "IP-based" : 
                                     packet.dpi_results.protocol === "HTTP" || packet.dpi_results.protocol === "HTTPS" ? "Web" : 
                                     packet.dpi_results.protocol === "DNS" ? "Domain" : "Other"}</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">Encryption:</span>
                              <span>{packet.dpi_results.protocol === "HTTPS" || packet.dpi_results.protocol === "TLS" ? "Encrypted" : "Unencrypted"}</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">Transport Protocol:</span>
                              <span>{packet.protocol}</span>
                            </div>
                          </div>
                        </div>
                        
                        <div>
                          <h4 className="text-sm font-medium mb-2">Content Classification</h4>
                          <div className="text-sm space-y-1">
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">Content Type:</span>
                              <span>{packet.dpi_results.protocol === "HTTP" || packet.dpi_results.protocol === "HTTPS" ? "Web Traffic" : 
                                     packet.dpi_results.protocol === "DNS" ? "DNS Query" :
                                     packet.dpi_results.protocol === "SMTP" ? "Email" : "Binary Data"}</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">Malformed Packet:</span>
                              <span>{packet.dpi_results.isSuspicious ? "Possible" : "No"}</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">Known Signatures:</span>
                              <span>{packet.dpi_results.findings && packet.dpi_results.findings.length > 0 ? "Matched" : "None Matched"}</span>
                            </div>
                          </div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                  
                  {packet.dpi_results.findings && packet.dpi_results.findings.length > 0 ? (
                    <Card>
                      <CardHeader className="pb-2">
                        <CardTitle className="text-lg">Payload Analysis Findings</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <ScrollArea className="h-[300px] rounded-md">
                          <div className="space-y-4">
                            {packet.dpi_results.findings.map((finding, index) => (
                              <div key={index} className="border p-4 rounded-md">
                                <div className="flex justify-between items-start mb-3">
                                  <h4 className="font-medium text-lg flex items-center">
                                    {finding.type}
                                    {finding.severity === "high" && <AlertCircle className="ml-2 h-4 w-4 text-red-500" />}
                                  </h4>
                                  <Badge variant="outline" className={cn(getThreatLevelClass(finding.severity))}>
                                    Severity: {finding.severity}
                                  </Badge>
                                </div>
                                
                                <p className="text-sm text-muted-foreground mb-3">{finding.description}</p>
                                
                                {finding.evidence && (
                                  <div className="mt-3 pt-3 border-t">
                                    <h5 className="text-sm font-medium mb-2">Evidence Found</h5>
                                    <div className="text-xs text-muted-foreground border rounded p-3 bg-slate-50 dark:bg-slate-900 overflow-auto">
                                      <code className="whitespace-pre-wrap break-all">{finding.evidence}</code>
                                    </div>
                                  </div>
                                )}
                                
                                <div className="grid md:grid-cols-2 gap-4 mt-4 pt-3 border-t">
                                  <div>
                                    <h5 className="text-sm font-medium mb-2">Analysis Details</h5>
                                    <ul className="text-sm space-y-1 text-muted-foreground">
                                      <li>• Pattern matched: {finding.type.replace(/_/g, ' ').toLowerCase()}</li>
                                      <li>• Location: packet payload</li>
                                      <li>• Matching algorithm: signature-based</li>
                                    </ul>
                                  </div>
                                  
                                  <div>
                                    <h5 className="text-sm font-medium mb-2">Recommendation</h5>
                                    <p className="text-sm text-muted-foreground">
                                      {finding.severity === "high" 
                                        ? "Block this traffic and investigate immediately." 
                                        : finding.severity === "medium"
                                        ? "Monitor closely and consider blocking if pattern continues."
                                        : "Low risk traffic pattern, monitor for changes."}
                                    </p>
                                  </div>
                                </div>
                              </div>
                            ))}
                          </div>
                        </ScrollArea>
                      </CardContent>
                    </Card>
                  ) : (
                    <div className="text-center py-8 text-muted-foreground bg-slate-50 dark:bg-slate-900 rounded-lg border p-6">
                      <Database className="mx-auto h-12 w-12 opacity-20 mb-2" />
                      <p>No suspicious patterns found in packet payload</p>
                      <p className="text-sm mt-2">Deep packet inspection did not detect any known malicious signatures</p>
                    </div>
                  )}
                </div>
              ) : (
                <div className="text-center py-4 text-muted-foreground">
                  No DPI results available for this packet
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
        
        <TabsContent value="behavioral" className="w-full">
          <Card className="w-full">
            <CardHeader>
              <CardTitle className="flex items-center">
                <Network className="mr-2 h-5 w-5" />
                Behavioral Analysis Results
              </CardTitle>
              <CardDescription>
                Analysis of network behavior patterns
              </CardDescription>
            </CardHeader>
            <CardContent>
              {packet.behavioral_results && packet.behavioral_results.anomalies && packet.behavioral_results.anomalies.length > 0 ? (
                <div className="space-y-4">
                  <Card className="bg-amber-500/5 border-amber-500/20">
                    <CardHeader className="pb-2">
                      <CardTitle className="text-amber-500 text-lg flex items-center">
                        <Server className="mr-2 h-4 w-4" />
                        Anomalies Detected
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <p className="text-sm text-muted-foreground">
                        {packet.behavioral_results.anomalies.length} behavioral anomaly pattern{packet.behavioral_results.anomalies.length > 1 ? 's were' : ' was'} detected in this traffic.
                      </p>
                      <div className="mt-3 grid md:grid-cols-3 gap-4">
                        <div>
                          <div className="text-sm font-medium">Anomaly Type</div>
                          <div className="font-semibold text-amber-600">
                            {packet.behavioral_results.anomalies[0].type}
                          </div>
                        </div>
                        <div>
                          <div className="text-sm font-medium">Detection Time</div>
                          <div className="font-semibold">
                            {formattedTime}
                          </div>
                        </div>
                        <div>
                          <div className="text-sm font-medium">Detection Method</div>
                          <div className="font-semibold">
                            Behavioral Pattern Analysis
                          </div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                  
                  <Card className="bg-slate-50 dark:bg-slate-900">
                    <CardHeader className="pb-2">
                      <CardTitle className="text-md flex items-center">
                        <Network className="mr-2 h-4 w-4" />
                        Connection Context
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="grid md:grid-cols-2 gap-6">
                        <div className="space-y-3">
                          <h4 className="text-sm font-medium">Communication Pattern</h4>
                          <div className="space-y-2">
                            <div className="flex justify-between text-sm">
                              <span className="text-muted-foreground">Connection Type:</span>
                              <span>{isSourcePrivate && isDestPrivate ? "Internal" : isSourcePrivate || isDestPrivate ? "External" : "Internet"}</span>
                            </div>
                            <div className="flex justify-between text-sm">
                              <span className="text-muted-foreground">Connection Direction:</span>
                              <span>{isSourcePrivate && !isDestPrivate ? "Outbound" : !isSourcePrivate && isDestPrivate ? "Inbound" : "Internal"}</span>
                            </div>
                            <div className="flex justify-between text-sm">
                              <span className="text-muted-foreground">Transport Protocol:</span>
                              <span>{packet.protocol}</span>
                            </div>
                          </div>
                        </div>
                        
                        <div className="space-y-3">
                          <h4 className="text-sm font-medium">Traffic Analysis</h4>
                          <div className="space-y-2">
                            <div className="flex justify-between text-sm">
                              <span className="text-muted-foreground">Expected Traffic:</span>
                              <span className="text-amber-600 font-medium">Abnormal</span>
                            </div>
                            <div className="flex justify-between text-sm">
                              <span className="text-muted-foreground">Baseline Match:</span>
                              <span>No match with normal patterns</span>
                            </div>
                            <div className="flex justify-between text-sm">
                              <span className="text-muted-foreground">Related Connections:</span>
                              <span>{packet.behavioral_results.anomalies[0].type === "PORT_SCAN" ? "Multiple" : "Single"}</span>
                            </div>
                          </div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                  
                  <ScrollArea className="h-[400px] rounded-md border">
                    <div className="p-4 space-y-4">
                      {packet.behavioral_results.anomalies.map((anomaly, index) => (
                        <Card key={index} className="border">
                          <CardHeader className="pb-2">
                            <CardTitle className="text-lg flex items-center">
                              {anomaly.type}
                              {anomaly.severity === "high" && <AlertCircle className="ml-2 h-4 w-4 text-red-500" />}
                            </CardTitle>
                          </CardHeader>
                          <CardContent className="space-y-3">
                            <p className="text-sm text-muted-foreground">{anomaly.description}</p>
                          
                            <div className="grid md:grid-cols-2 gap-4 mt-2">
                              <div>
                                <h5 className="text-sm font-medium mb-2">Anomaly Classification</h5>
                                <ul className="text-sm space-y-1 text-muted-foreground">
                                  <li className="flex items-start">
                                    <span className="mr-2">•</span>
                                    <span>Category: {anomaly.type.includes("PORT_SCAN") ? "Reconnaissance" : 
                                                      anomaly.type.includes("VOLUME") ? "Volumetric" : 
                                                      anomaly.type.includes("CONNECTION") ? "Connection-based" : "Unknown"}</span>
                                  </li>
                                  <li className="flex items-start">
                                    <span className="mr-2">•</span>
                                    <span>Pattern: {anomaly.type.includes("PORT_SCAN") ? "Multiple ports accessed sequentially" : 
                                                    anomaly.type.includes("VOLUME") ? "Abnormal traffic volume" : 
                                                    anomaly.type.includes("CONNECTION") ? "Excessive connection attempts" : "Undefined"}</span>
                                  </li>
                                  <li className="flex items-start">
                                    <span className="mr-2">•</span>
                                    <span>Time Frame: {packet.timestamp_start && packet.timestamp_end ? `${((packet.timestamp_end - packet.timestamp_start) / 1000).toFixed(2)} seconds` : "Unknown"}</span>
                                  </li>
                                </ul>
                              </div>
                              
                              <div>
                                <h5 className="text-sm font-medium mb-2">Risk Assessment</h5>
                                <div className="space-y-3">
                                  <div className="flex justify-between text-sm">
                                    <Badge variant="outline" className={cn(getThreatLevelClass(anomaly.severity))}>
                                      Severity: {anomaly.severity}
                                    </Badge>
                                    {anomaly.confidence && (
                                      <Badge variant="outline">
                                        Confidence: {Math.round(anomaly.confidence * 100)}%
                                      </Badge>
                                    )}
                                  </div>
                                  <p className="text-sm text-muted-foreground">
                                    {anomaly.severity === "high" 
                                      ? "High likelihood of malicious activity. Immediate investigation recommended."
                                      : anomaly.severity === "medium"
                                      ? "Moderate risk. Monitor and investigate if pattern continues."
                                      : "Low risk but outside normal baseline. Monitor for escalation."}
                                  </p>
                                </div>
                              </div>
                            </div>
                            
                            <div className="mt-3 pt-3 border-t">
                              <h5 className="text-sm font-medium mb-2">Recommended Action</h5>
                              <p className="text-sm text-muted-foreground">
                                {anomaly.type.includes("PORT_SCAN") 
                                  ? "Block source IP immediately and investigate for potential intrusion attempts. Update firewall rules."
                                  : anomaly.type.includes("VOLUME") 
                                  ? "Implement rate limiting for this source IP and monitor for potential DoS activity."
                                  : anomaly.type.includes("CONNECTION") 
                                  ? "Review connection patterns and implement connection limits if appropriate."
                                  : "Monitor for continued suspicious behavior from this source/destination pair."}
                              </p>
                            </div>
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  </ScrollArea>
                </div>
              ) : (
                <div className="space-y-6">
                  <div className="text-center py-8 text-muted-foreground">
                    <Network className="mx-auto h-12 w-12 opacity-20 mb-2" />
                    <p>No behavioral anomalies detected for this packet</p>
                    <p className="text-sm mt-2">This packet shows normal network behavior patterns</p>
                  </div>
                  
                  <Card className="bg-slate-50 dark:bg-slate-900">
                    <CardHeader className="pb-2">
                      <CardTitle className="text-md flex items-center">
                        <Network className="mr-2 h-4 w-4" />
                        Behavioral Assessment
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="grid md:grid-cols-2 gap-6">
                        <div className="space-y-3">
                          <h4 className="text-sm font-medium">Communication Pattern</h4>
                          <div className="space-y-2">
                            <div className="flex justify-between text-sm">
                              <span className="text-muted-foreground">Connection Type:</span>
                              <span>{isSourcePrivate && isDestPrivate ? "Internal" : isSourcePrivate || isDestPrivate ? "External" : "Internet"}</span>
                            </div>
                            <div className="flex justify-between text-sm">
                              <span className="text-muted-foreground">Connection Direction:</span>
                              <span>{isSourcePrivate && !isDestPrivate ? "Outbound" : !isSourcePrivate && isDestPrivate ? "Inbound" : "Internal"}</span>
                            </div>
                            <div className="flex justify-between text-sm">
                              <span className="text-muted-foreground">Transport Protocol:</span>
                              <span>{packet.protocol}</span>
                            </div>
                          </div>
                        </div>
                        
                        <div className="space-y-3">
                          <h4 className="text-sm font-medium">Traffic Analysis</h4>
                          <div className="space-y-2">
                            <div className="flex justify-between text-sm">
                              <span className="text-muted-foreground">Expected Traffic:</span>
                              <span className="text-green-600 font-medium">Normal</span>
                            </div>
                            <div className="flex justify-between text-sm">
                              <span className="text-muted-foreground">Baseline Match:</span>
                              <span>Matches normal patterns</span>
                            </div>
                            <div className="flex justify-between text-sm">
                              <span className="text-muted-foreground">Port Usage:</span>
                              <span>{getPortService(packet.dst_port) === "Unknown" ? "Non-standard" : "Standard"}</span>
                            </div>
                          </div>
                        </div>
                      </div>
                      
                      <div className="mt-4 pt-4 border-t">
                        <div className="text-sm font-medium mb-2">Assessment Summary</div>
                        <p className="text-sm text-muted-foreground">
                          This packet exhibits normal network behavior with no signs of anomalous activity.
                          The communication follows expected patterns for the {packet.protocol} protocol and
                          standard service on port {packet.dst_port} ({getPortService(packet.dst_port)}).
                          {isSourcePrivate && isDestPrivate && " As this is internal network traffic, it has a lower risk profile."} 
                          No further analysis required.
                        </p>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
        
        <TabsContent value="payload" className="w-full">
          <Card className="w-full">
            <CardHeader>
              <CardTitle className="flex items-center">
                <Eye className="mr-2 h-5 w-5" />
                Raw Packet Payload
              </CardTitle>
              <CardDescription>
                Base64 encoded packet payload data with decoded view
              </CardDescription>
            </CardHeader>
            <CardContent>
              {packet.payload ? (
                <div className="space-y-6">
                  <Card className="border-2 border-dashed">
                    <CardHeader className="pb-2">
                      <CardTitle className="text-md">Base64 Encoded Data</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <ScrollArea className="h-[100px] rounded-md border p-4 font-mono text-xs">
                        {packet.payload}
                      </ScrollArea>
                    </CardContent>
                  </Card>
                  
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-md">Decoded Data</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-4">
                        <ScrollArea className="h-[150px] rounded-md border p-4 font-mono text-xs">
                          {(() => {
                            try {
                              // Decode base64
                              const decodedText = atob(packet.payload);
                              return decodedText.replace(/[^\x20-\x7E]/g, '·'); // Replace non-printable chars
                            } catch (error) {
                              console.error("Error decoding payload:", error);
                              return "Unable to decode payload data";
                            }
                          })()}
                        </ScrollArea>
                        
                        <div className="text-xs text-muted-foreground">
                          <p>Note: Non-printable characters are replaced with &apos;·&apos; for readability</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                  
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-md">Hexdump View</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <ScrollArea className="h-[200px] rounded-md border p-4 font-mono text-xs">
                        {(() => {
                          try {
                            // Decode base64
                            const decodedBytes = atob(packet.payload);
                            let hexOutput = '';
                            
                            for (let i = 0; i < decodedBytes.length; i += 16) {
                              // Address
                              const addr = i.toString(16).padStart(8, '0');
                              hexOutput += `${addr}  `;
                              
                              // Hex values
                              for (let j = 0; j < 16; j++) {
                                if (i + j < decodedBytes.length) {
                                  const byte = decodedBytes.charCodeAt(i + j);
                                  hexOutput += byte.toString(16).padStart(2, '0') + ' ';
                                } else {
                                  hexOutput += '   ';
                                }
                                
                                if (j === 7) hexOutput += ' ';
                              }
                              
                              // ASCII representation
                              hexOutput += ' |';
                              for (let j = 0; j < 16; j++) {
                                if (i + j < decodedBytes.length) {
                                  const byte = decodedBytes.charCodeAt(i + j);
                                  const char = byte >= 32 && byte <= 126 ? decodedBytes[i + j] : '.';
                                  hexOutput += char;
                                } else {
                                  hexOutput += ' ';
                                }
                              }
                              hexOutput += '|\n';
                            }
                            
                            return hexOutput;
                          } catch (error) {
                            console.error("Error creating hexdump:", error);
                            return "Unable to create hexdump view";
                          }
                        })()}
                      </ScrollArea>
                    </CardContent>
                  </Card>
                </div>
              ) : (
                <div className="text-center py-8 text-muted-foreground">
                  <Eye className="mx-auto h-12 w-12 opacity-20 mb-2" />
                  <p>No payload data available for this packet</p>
                  <p className="text-sm mt-2">The packet payload was not captured or is empty</p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

/*export default async function PacketPage({ 
  params 
}: { 
  params: { id: string } 
}) {
  // Make sure we're using the params correctly in an async context
  const { id } = params;
  
  return (
    <div className="flex-1 space-y-4 p-4 md:p-8 pt-6">
      <Suspense fallback={<div className="text-center py-10">Loading packet details...</div>}>
        <PacketDetails id={id} />
      </Suspense>
    </div>
  );
}*/
export default async function PacketPage({ params }: { params: { id?: string }}) {
  if (!params?.id) {
    return <div className="text-center py-10 text-red-500">Invalid Packet ID</div>;
  }

  return (
    <div className="flex-1 space-y-4 p-4 md:p-8 pt-6">
      <Suspense fallback={<div className="text-center py-10">Loading packet details...</div>}>
        <PacketDetails id={params.id} />
      </Suspense>
    </div>
  );
} 