'use client'

import { Suspense } from "react"
import { useState, useEffect } from "react"
import { motion } from "framer-motion"
import { FileText, ShieldAlert, Network, Database, Activity } from "lucide-react"

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { LoadingSpinner } from "@/components/ui/loading-spinner"
import { ServiceMetricsCards, ServiceMetricsCharts } from "@/components/metrics/service-metrics"
import { AlertsSummaryCards } from "@/components/alerts/alerts-summary"
import { ServiceStatusCards } from "@/components/services/service-status"
import Link from "next/link"
import { Packet } from "@/lib/packets"

export default function DashboardPage() {
    const [mounted, setMounted] = useState(false)
    const [packetStats, setPacketStats] = useState({
        total: 0,
        safe: 0,
        unsafe: 0,
        protocols: {} as Record<string, number>,
        lastUpdated: new Date()
    })

    useEffect(() => {
        setMounted(true)
        fetchPacketStats()
        
        const intervalId = setInterval(fetchPacketStats, 20000)
        return () => clearInterval(intervalId)
    }, [])
    
    const fetchPacketStats = async () => {
        try {
            const response = await fetch("/api/packets?limit=100", {
                cache: "no-store"
            })
            
            if (response.ok) {
                const packets = await response.json() as Packet[]
                const total = packets.length
                const safe = packets.filter((p: Packet) => p.status === "Safe").length
                const unsafe = packets.filter((p: Packet) => p.status === "Unsafe").length
                
                const protocols = packets.reduce((acc: Record<string, number>, packet: Packet) => {
                    const protocol = packet.protocol
                    acc[protocol] = (acc[protocol] || 0) + 1
                    return acc
                }, {} as Record<string, number>)
                
                setPacketStats({
                    total,
                    safe,
                    unsafe,
                    protocols,
                    lastUpdated: new Date()
                })
            }
        } catch (error) {
            console.error("Error fetching packet stats:", error)
        }
    }

    if (!mounted) {
        return null
    }
    const container = {
        hidden: { opacity: 0 },
        show: {
            opacity: 1,
            transition: {
                staggerChildren: 0.1,
            },
        },
    }

    const item = {
        hidden: { opacity: 0, y: 20 },
        show: { opacity: 1, y: 0 },
    }

    // Helper function to get the top protocol safely
    const getTopProtocol = (): string => {
        if (Object.entries(packetStats.protocols).length === 0) {
            return "N/A"
        }
        return Object.entries(packetStats.protocols)
            .sort((a: [string, number], b: [string, number]) => b[1] - a[1])[0][0]
    }

    return (
        <div className="flex flex-col min-h-screen p-6 bg-background">
            <motion.div
                initial={{ opacity: 0, y: -20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5 }}
                className="flex flex-col md:flex-row justify-between items-start md:items-center mb-8 gap-4"
            >
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">Network Dashboard</h1>
                    <p className="text-muted-foreground">Monitor your network traffic and packet security analysis</p>
                </div>
                <div className="flex items-center gap-4">
                    <Link href="/sniffer">
                        <Button variant="default" size="sm">
                            <Network className="mr-2 h-4 w-4" />
                            Live Sniffer
                        </Button>
                    </Link>
                    <Button variant="outline" size="sm">
                        <FileText className="mr-2 h-4 w-4" />
                        Export Report
                    </Button>
                </div>
            </motion.div>

            <Tabs defaultValue="overview" className="w-full">
                <TabsList className="mb-6">
                    <TabsTrigger value="overview">Network Overview</TabsTrigger>
                    <TabsTrigger value="metrics">Analysis Metrics</TabsTrigger>
                    <TabsTrigger value="alerts">Alerts</TabsTrigger>
                </TabsList>
                
                <TabsContent value="overview">
                    <motion.div variants={container} initial="hidden" animate="show" className="flex flex-col gap-6">
                        <motion.div variants={item}>
                            <Card>
                                <CardHeader>
                                    <CardTitle>Network Traffic Overview</CardTitle>
                                    <CardDescription>
                                        Overview of network traffic and security status
                                    </CardDescription>
                                </CardHeader>
                                <CardContent className="px-2">
                                    <div className="grid gap-6">
                                        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                                            <Card>
                                                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                                                    <CardTitle className="text-sm font-medium">
                                                        Total Packets
                                                    </CardTitle>
                                                    <Activity className="h-4 w-4 text-muted-foreground" />
                                                </CardHeader>
                                                <CardContent>
                                                    <div className="text-2xl font-bold">{packetStats.total}</div>
                                                    <p className="text-xs text-muted-foreground">
                                                        Last updated: {packetStats.lastUpdated.toLocaleTimeString()}
                                                    </p>
                                                </CardContent>
                                            </Card>
                                            <Card className="bg-green-500/5">
                                                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                                                    <CardTitle className="text-sm font-medium">
                                                        Safe Traffic
                                                    </CardTitle>
                                                    <ShieldAlert className="h-4 w-4 text-green-500" />
                                                </CardHeader>
                                                <CardContent>
                                                    <div className="text-2xl font-bold text-green-500">{packetStats.safe}</div>
                                                    <p className="text-xs text-muted-foreground">
                                                        {packetStats.total > 0 ? Math.round((packetStats.safe / packetStats.total) * 100) : 0}% of total traffic
                                                    </p>
                                                </CardContent>
                                            </Card>
                                            <Card className="bg-red-500/5">
                                                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                                                    <CardTitle className="text-sm font-medium">
                                                        Unsafe Traffic
                                                    </CardTitle>
                                                    <ShieldAlert className="h-4 w-4 text-red-500" />
                                                </CardHeader>
                                                <CardContent>
                                                    <div className="text-2xl font-bold text-red-500">{packetStats.unsafe}</div>
                                                    <p className="text-xs text-muted-foreground">
                                                        {packetStats.total > 0 ? Math.round((packetStats.unsafe / packetStats.total) * 100) : 0}% of total traffic
                                                    </p>
                                                </CardContent>
                                            </Card>
                                            <Card>
                                                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                                                    <CardTitle className="text-sm font-medium">
                                                        Top Protocol
                                                    </CardTitle>
                                                    <Database className="h-4 w-4 text-muted-foreground" />
                                                </CardHeader>
                                                <CardContent>
                                                    <div className="text-2xl font-bold">
                                                        {getTopProtocol()}
                                                    </div>
                                                    <p className="text-xs text-muted-foreground">
                                                        Most common protocol in traffic
                                                    </p>
                                                </CardContent>
                                            </Card>
                                        </div>

                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                            <Card>
                                                <CardHeader>
                                                    <CardTitle className="text-lg">Recent Network Activity</CardTitle>
                                                    <CardDescription>Latest traffic analysis and security events</CardDescription>
                                                </CardHeader>
                                                <CardContent>
                                                    <div className="space-y-4">
                                                        <div className="flex items-center">
                                                            <div className="w-2 h-2 rounded-full bg-green-500 mr-2"></div>
                                                            <div className="text-sm">Network monitoring active and receiving packets</div>
                                                        </div>
                                                        <div className="flex items-center">
                                                            <div className="w-2 h-2 rounded-full bg-blue-500 mr-2"></div>
                                                            <div className="text-sm">Deep packet inspection analyzing traffic in real-time</div>
                                                        </div>
                                                        <div className="flex items-center">
                                                            <div className="w-2 h-2 rounded-full bg-amber-500 mr-2"></div>
                                                            <div className="text-sm">Threat detection rules updated and active</div>
                                                        </div>
                                                        {packetStats.unsafe > 0 && (
                                                            <div className="flex items-center">
                                                                <div className="w-2 h-2 rounded-full bg-red-500 mr-2"></div>
                                                                <div className="text-sm">{packetStats.unsafe} potentially malicious packets detected</div>
                                                            </div>
                                                        )}
                                                    </div>
                                                    <div className="mt-4 pt-4 border-t">
                                                        <Link href="/sniffer">
                                                            <Button variant="outline" className="w-full">View Live Traffic</Button>
                                                        </Link>
                                                    </div>
                                                </CardContent>
                                            </Card>
                                            
                                            <Card>
                                                <CardHeader>
                                                    <CardTitle className="text-lg">System Status</CardTitle>
                                                    <CardDescription>Packet capture and analysis system</CardDescription>
                                                </CardHeader>
                                                <CardContent>
                                                    <div className="space-y-4">
                                                        <div className="flex items-center justify-between">
                                                            <span className="text-sm font-medium">Capture Service</span>
                                                            <span className="text-xs bg-green-500/20 text-green-600 px-2 py-1 rounded-full">Active</span>
                                                        </div>
                                                        <div className="flex items-center justify-between">
                                                            <span className="text-sm font-medium">Analysis Engine</span>
                                                            <span className="text-xs bg-green-500/20 text-green-600 px-2 py-1 rounded-full">Active</span>
                                                        </div>
                                                        <div className="flex items-center justify-between">
                                                            <span className="text-sm font-medium">DPI Module</span>
                                                            <span className="text-xs bg-green-500/20 text-green-600 px-2 py-1 rounded-full">Active</span>
                                                        </div>
                                                        <div className="flex items-center justify-between">
                                                            <span className="text-sm font-medium">Behavioral Analysis</span>
                                                            <span className="text-xs bg-green-500/20 text-green-600 px-2 py-1 rounded-full">Active</span>
                                                        </div>
                                                        <div className="flex items-center justify-between">
                                                            <span className="text-sm font-medium">System Updates</span>
                                                            <span className="text-xs bg-blue-500/20 text-blue-600 px-2 py-1 rounded-full">Up to date</span>
                                                        </div>
                                                    </div>
                                                    <div className="mt-4 pt-4 border-t">
                                                        <div className="text-sm text-muted-foreground">Last system check: Today at {new Date().toLocaleTimeString()}</div>
                                                    </div>
                                                </CardContent>
                                            </Card>
                                        </div>
                                    </div>
                                </CardContent>
                            </Card>
                        </motion.div>
                    </motion.div>
                </TabsContent>

                <TabsContent value="metrics">
                    <motion.div variants={container} initial="hidden" animate="show" className="flex flex-col gap-6">
                        <motion.div variants={item}>
                            <Card>
                                <CardHeader>
                                    <CardTitle>Analysis Service Metrics</CardTitle>
                                    <CardDescription>
                                        Key performance indicators from the network packet analysis service
                                    </CardDescription>
                                </CardHeader>
                                <CardContent className="px-2">
                                    <div className="grid gap-6">
                                        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                                            <Suspense fallback={<LoadingSpinner message="Loading service status..." />}>
                                                <ServiceStatusCards />
                                            </Suspense>
                                        </div>

                                        <div className="grid grid-cols-1 gap-6">
                                            <Suspense fallback={<LoadingSpinner message="Loading metrics..." />}>
                                                <div className="space-y-6">
                                                    <div>
                                                        <h3 className="text-lg font-medium mb-4">Key Performance Indicators</h3>
                                                        <ServiceMetricsCards />
                                                    </div>

                                                    <div>
                                                        <h3 className="text-lg font-medium mb-4">Detailed Analytics</h3>
                                                        <ServiceMetricsCharts />
                                                    </div>
                                                </div>
                                            </Suspense>
                                        </div>
                                    </div>
                                </CardContent>
                            </Card>
                        </motion.div>
                    </motion.div>
                </TabsContent>

                <TabsContent value="alerts">
                    <motion.div
                        variants={container}
                        initial="hidden"
                        animate="show"
                    >
                        <motion.div variants={item}>
                            <Suspense fallback={<LoadingSpinner message="Loading alerts..." />}>
                                <AlertsSummaryCards />
                            </Suspense>
                        </motion.div>
                    </motion.div>
                </TabsContent>
            </Tabs>
        </div>
    )
}