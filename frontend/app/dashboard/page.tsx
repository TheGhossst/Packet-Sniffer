'use client'

import { Suspense } from "react"
import { useState, useEffect } from "react"
import { motion } from "framer-motion"
import { FileText } from "lucide-react"

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { LoadingSpinner } from "@/components/ui/loading-spinner"
import { ServiceMetricsCards, ServiceMetricsCharts } from "@/components/metrics/service-metrics"
import { AlertsSummaryCards } from "@/components/alerts/alerts-summary"
import { ServiceStatusCards } from "@/components/services/service-status"

export default function DashboardPage() {
    const [mounted, setMounted] = useState(false)

    useEffect(() => {
        setMounted(true)
    }, [])

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

    return (
        <div className="flex flex-col min-h-screen p-6 bg-background">
            <motion.div
                initial={{ opacity: 0, y: -20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5 }}
                className="flex flex-col md:flex-row justify-between items-start md:items-center mb-8 gap-4"
            >
                <div>
                    <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
                    <p className="text-muted-foreground">Monitor your network traffic and system performance</p>
                </div>
                <div className="flex items-center gap-4">
                    <Button variant="outline" size="sm">
                        <FileText className="mr-2 h-4 w-4" />
                        Export Report
                    </Button>
                </div>
            </motion.div>

            <Tabs defaultValue="metrics" className="w-full">
                <TabsList className="mb-6">
                    <TabsTrigger value="metrics">Analysis Metrics</TabsTrigger>
                    <TabsTrigger value="alerts">Alerts</TabsTrigger>
                </TabsList>

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

                                        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                                            <div className="col-span-3">
                                                <Card>
                                                    <CardContent className="pt-6">
                                                        <div className="grid gap-4">
                                                            <div>
                                                                <h4 className="font-medium mb-1">About the Analysis Service</h4>
                                                                <p className="text-sm text-muted-foreground">
                                                                    The analysis service processes network packets and analyzes them for potential
                                                                    security threats. Metrics shown here provide insights into the service&apos;s
                                                                    performance and detection capabilities.
                                                                </p>
                                                            </div>

                                                            <div>
                                                                <h4 className="font-medium mb-1">Enhanced Detection</h4>
                                                                <p className="text-sm text-muted-foreground">
                                                                    IP detection uses the <a href="https://github.com/stamparm/ipsum" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">IPSUM blacklist feed</a> for
                                                                    identifying potentially malicious traffic. Packets are marked as &quot;Safe&quot; or &quot;Unsafe&quot; rather than &quot;BENIGN&quot; or &quot;MALICIOUS&quot;.
                                                                </p>
                                                            </div>

                                                            <div>
                                                                <h4 className="font-medium mb-1">Safe IPs List</h4>
                                                                <p className="text-sm text-muted-foreground">
                                                                    The analysis service maintains a list of known safe IPs to reduce false positives
                                                                    and provide more accurate threat detection.
                                                                </p>
                                                            </div>

                                                            <div>
                                                                <h4 className="font-medium mb-1">External API Integration</h4>
                                                                <p className="text-sm text-muted-foreground">
                                                                    The service integrates with external threat intelligence APIs (VirusTotal, AbuseIPDB) to enrich detection capabilities.
                                                                    API metrics show successful detections, errors, and timeouts for comprehensive monitoring.
                                                                </p>
                                                            </div>
                                                        </div>
                                                    </CardContent>
                                                </Card>
                                            </div>
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