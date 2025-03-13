"use client"

import { useState, useEffect } from "react"
import Link from "next/link"
import { motion, useScroll, useTransform } from "framer-motion"
import { ArrowRight, Database, ExternalLink, Network, Play, Shield, Zap, Check } from "lucide-react"
import { Button } from "@/components/ui/button"

export default function LandingPage() {
  const [mounted, setMounted] = useState(false)
  const { scrollYProgress } = useScroll()
  const opacity = useTransform(scrollYProgress, [0, 0.2], [1, 0])
  const scale = useTransform(scrollYProgress, [0, 0.2], [1, 0.9])

  useEffect(() => {
    setMounted(true)
  }, [])

  if (!mounted) {
    return null
  }

  const features = [
    {
      icon: Network,
      title: "Real-time Packet Analysis",
      description: "Monitor network traffic with microsecond precision and detailed protocol inspection.",
    },
    {
      icon: Zap,
      title: "High Performance",
      description: "Built with Go for maximum efficiency, capable of handling gigabit network speeds.",
    },
    {
      icon: Database,
      title: "Redis Integration",
      description: "Store and query packet data with lightning-fast Redis database integration.",
    }
  ]

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
    <div className="flex flex-col min-h-screen bg-background">
      <header className="fixed top-0 left-0 right-0 z-50 bg-background/80 backdrop-blur-md border-b border-border">
        <div className="container mx-auto px-4 md:px-6 flex items-center justify-center h-16">
          <div className="flex w-full max-w-7xl items-center justify-between">
            <Link href="/" className="flex items-center gap-2">
              <Network className="h-6 w-6 text-primary" />
              <span className="font-bold text-xl">PacketVigil</span>
            </Link>
            <nav className="hidden md:flex items-center gap-6">
              <Link
                href="#features"
                className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors"
              >
                Features
              </Link>
              <Link
                href="#performance"
                className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors"
              >
                Performance
              </Link>
              <Link
                href="#security"
                className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors"
              >
                Security
              </Link>
              <Link
                href="/documentation"
                className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1"
              >
                Documentation <ExternalLink className="h-3 w-3" />
              </Link>
            </nav>
            <div className="flex items-center gap-4">
              <Button asChild variant="outline" size="sm" className="hidden md:inline-flex">
                <Link href="/dashboard">Dashboard</Link>
              </Button>
              <Button asChild size="sm">
                <Link href="/sniffer">
                  <Play className="mr-1 h-3 w-3" />
                  Start Sniffing
                </Link>
              </Button>
            </div>
          </div>
        </div>
      </header>

      <section className="relative pt-32 pb-20 md:pt-40 md:pb-32 overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-background via-background to-primary/10 z-0" />
        <motion.div style={{ opacity, scale }} className="absolute inset-0 z-0 flex items-center justify-center">
          <div className="absolute top-1/4 left-1/4 w-1/2 h-1/2 bg-primary/5 rounded-full filter blur-3xl" />
          <div className="absolute top-1/3 left-1/3 w-1/3 h-1/3 bg-blue-500/5 rounded-full filter blur-2xl" />
        </motion.div>

        <div className="container relative z-10 px-4 md:px-6 mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="flex flex-col items-center text-center space-y-4 mb-12"
          >
            <motion.div
              initial={{ scale: 0.8, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              transition={{ duration: 0.5, delay: 0.2 }}
              className="relative"
            >
              <div className="absolute inset-0 bg-primary/20 rounded-full filter blur-xl" />
              <Network className="h-20 w-20 text-primary mb-4 relative z-10" />
            </motion.div>
            <motion.h1
              className="text-5xl md:text-7xl font-bold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-white to-gray-400"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.3 }}
            >
              PacketVigil
            </motion.h1>
            <motion.p
              className="text-xl md:text-2xl text-muted-foreground max-w-[800px]"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.4 }}
            >
              Advanced packet sniffing and network analysis platform built with Go, Redis, and Node.js
            </motion.p>
            <motion.div
              className="flex flex-col sm:flex-row gap-4 mt-8"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.5 }}
            >
              <Button asChild size="lg" className="px-8">
                <Link href="/sniffer">
                  Start Sniffing <ArrowRight className="ml-2 h-4 w-4" />
                </Link>
              </Button>
            </motion.div>
          </motion.div>

          <motion.div
            className="relative h-[400px] md:h-[500px] mt-12 mb-20 mx-auto max-w-5xl"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 1, delay: 0.6 }}
          >
            <EnhancedNetworkAnimation />
          </motion.div>
        </div>
      </section>

      <section id="features" className="py-20 bg-black/20">
        <div className="container px-4 md:px-6 mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5 }}
            className="text-center mb-16"
          >
            <div className="inline-block bg-primary/10 px-3 py-1 rounded-full text-primary text-sm font-medium mb-4">
              Powerful Features
            </div>
            <h2 className="text-4xl md:text-5xl font-bold mb-4">Enterprise-Grade Network Analysis</h2>
            <p className="text-muted-foreground max-w-[800px] mx-auto text-lg">
              PacketVigil provides comprehensive network monitoring capabilities with an intuitive interface
            </p>
          </motion.div>

          <motion.div
            variants={container}
            initial="hidden"
            whileInView="show"
            viewport={{ once: true }}
            className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8 max-w-6xl mx-auto"
          >
            {features.map((feature, index) => (
              <motion.div
                key={index}
                variants={item}
                whileHover={{ y: -5, transition: { duration: 0.2 } }}
                className="bg-card border border-border rounded-xl p-8 hover:shadow-lg hover:shadow-primary/5 transition-all"
              >
                <div className="bg-primary/10 p-4 rounded-full w-fit mb-6">
                  <feature.icon className="h-8 w-8 text-primary" />
                </div>
                <h3 className="text-2xl font-semibold mb-3">{feature.title}</h3>
                <p className="text-muted-foreground">{feature.description}</p>
              </motion.div>
            ))}
          </motion.div>
        </div>
      </section>
      <section id="performance" className="py-24 relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-blue-500/5 via-background to-background z-0" />
        <div className="container px-4 md:px-6 relative z-10 mx-auto">
          <div className="grid md:grid-cols-2 gap-12 items-center max-w-6xl mx-auto">
            <motion.div
              initial={{ opacity: 0, x: -20 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5 }}
            >
              <div className="inline-block bg-blue-500/10 px-3 py-1 rounded-full text-blue-500 text-sm font-medium mb-4">
                High Performance
              </div>
              <h2 className="text-4xl font-bold mb-6">Lightning-Fast Packet Processing</h2>
              <p className="text-muted-foreground mb-6 text-lg">
                Built with performance in mind, packeytm can handle gigabit network speeds with minimal resource usage.
              </p>

              <div className="space-y-4">
                <div className="flex items-start gap-3">
                  <div className="bg-blue-500/10 p-1 rounded-full mt-1">
                    <Check className="h-4 w-4 text-blue-500" />
                  </div>
                  <div>
                    <h4 className="font-medium">Go-powered Backend</h4>
                    <p className="text-sm text-muted-foreground">Optimized for speed and efficiency</p>
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <div className="bg-blue-500/10 p-1 rounded-full mt-1">
                    <Check className="h-4 w-4 text-blue-500" />
                  </div>
                  <div>
                    <h4 className="font-medium">Redis Integration</h4>
                    <p className="text-sm text-muted-foreground">In-memory database for ultra-fast queries</p>
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <div className="bg-blue-500/10 p-1 rounded-full mt-1">
                    <Check className="h-4 w-4 text-blue-500" />
                  </div>
                  <div>
                    <h4 className="font-medium">Optimized Packet Processing</h4>
                    <p className="text-sm text-muted-foreground">Process millions of packets with minimal CPU usage</p>
                  </div>
                </div>
              </div>

              <Button asChild className="mt-8">
                <Link href="/dashboard">View Performance Metrics</Link>
              </Button>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, x: 20 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: 0.2 }}
              className="relative"
            >
              <div className="absolute inset-0 bg-blue-500/5 rounded-3xl filter blur-xl" />
              <div className="relative bg-card border border-border rounded-3xl p-6 shadow-xl">
                <div className="flex items-center justify-between mb-6">
                  <div className="flex items-center gap-2">
                    <div className="h-3 w-3 rounded-full bg-red-500" />
                    <div className="h-3 w-3 rounded-full bg-yellow-500" />
                    <div className="h-3 w-3 rounded-full bg-green-500" />
                  </div>
                  <div className="text-xs text-muted-foreground">Performance Metrics</div>
                </div>

                <div className="space-y-6">
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span>Packet Processing Rate</span>
                      <span className="font-mono">1.2M pkts/sec</span>
                    </div>
                    <div className="h-2 w-full bg-muted rounded-full overflow-hidden">
                      <motion.div
                        className="h-full bg-blue-500"
                        initial={{ width: "0%" }}
                        whileInView={{ width: "85%" }}
                        viewport={{ once: true }}
                        transition={{ duration: 1, delay: 0.5 }}
                      />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span>Memory Usage</span>
                      <span className="font-mono">256 MB</span>
                    </div>
                    <div className="h-2 w-full bg-muted rounded-full overflow-hidden">
                      <motion.div
                        className="h-full bg-green-500"
                        initial={{ width: "0%" }}
                        whileInView={{ width: "35%" }}
                        viewport={{ once: true }}
                        transition={{ duration: 1, delay: 0.6 }}
                      />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span>CPU Utilization</span>
                      <span className="font-mono">15%</span>
                    </div>
                    <div className="h-2 w-full bg-muted rounded-full overflow-hidden">
                      <motion.div
                        className="h-full bg-purple-500"
                        initial={{ width: "0%" }}
                        whileInView={{ width: "15%" }}
                        viewport={{ once: true }}
                        transition={{ duration: 1, delay: 0.7 }}
                      />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span>Network Throughput</span>
                      <span className="font-mono">10 Gbps</span>
                    </div>
                    <div className="h-2 w-full bg-muted rounded-full overflow-hidden">
                      <motion.div
                        className="h-full bg-primary"
                        initial={{ width: "0%" }}
                        whileInView={{ width: "75%" }}
                        viewport={{ once: true }}
                        transition={{ duration: 1, delay: 0.8 }}
                      />
                    </div>
                  </div>
                </div>

                <div className="mt-8 pt-6 border-t border-border">
                  <div className="grid grid-cols-3 gap-4 text-center">
                    <div>
                      <div className="text-2xl font-bold">99.9%</div>
                      <div className="text-xs text-muted-foreground">Uptime</div>
                    </div>
                    <div>
                      <div className="text-2xl font-bold">0.5ms</div>
                      <div className="text-xs text-muted-foreground">Latency</div>
                    </div>
                    <div>
                      <div className="text-2xl font-bold">100%</div>
                      <div className="text-xs text-muted-foreground">Accuracy</div>
                    </div>
                  </div>
                </div>
              </div>
            </motion.div>
          </div>
        </div>
      </section>

      <section id="security" className="py-24 bg-black/20">
        <div className="container px-4 md:px-6 mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5 }}
            className="text-center mb-16"
          >
            <div className="inline-block bg-red-500/10 px-3 py-1 rounded-full text-red-500 text-sm font-medium mb-4">
              Security
            </div>
            <h2 className="text-4xl md:text-5xl font-bold mb-4">Detect Threats in Real-Time</h2>
            <p className="text-muted-foreground max-w-[800px] mx-auto text-lg">
              Identify suspicious network activity and potential security breaches before they cause damage
            </p>
          </motion.div>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8 max-w-6xl mx-auto">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5 }}
              className="col-span-full lg:col-span-1 bg-card border border-border rounded-xl p-8"
            >
              <h3 className="text-2xl font-bold mb-4">Security Features</h3>
              <ul className="space-y-4">
                <li className="flex items-start gap-3">
                  <div className="bg-red-500/10 p-1 rounded-full mt-1">
                    <Shield className="h-4 w-4 text-red-500" />
                  </div>
                  <div>
                    <h4 className="font-medium">Intrusion Detection</h4>
                    <p className="text-sm text-muted-foreground">Identify potential network intrusions and attacks</p>
                  </div>
                </li>
                <li className="flex items-start gap-3">
                  <div className="bg-red-500/10 p-1 rounded-full mt-1">
                    <Shield className="h-4 w-4 text-red-500" />
                  </div>
                  <div>
                    <h4 className="font-medium">Anomaly Detection</h4>
                    <p className="text-sm text-muted-foreground">Detect unusual traffic patterns and behaviors</p>
                  </div>
                </li>
                <li className="flex items-start gap-3">
                  <div className="bg-red-500/10 p-1 rounded-full mt-1">
                    <Shield className="h-4 w-4 text-red-500" />
                  </div>
                  <div>
                    <h4 className="font-medium">Malware Detection</h4>
                    <p className="text-sm text-muted-foreground">Identify potential malware communication</p>
                  </div>
                </li>
                <li className="flex items-start gap-3">
                  <div className="bg-red-500/10 p-1 rounded-full mt-1">
                    <Shield className="h-4 w-4 text-red-500" />
                  </div>
                  <div>
                    <h4 className="font-medium">Data Exfiltration Prevention</h4>
                    <p className="text-sm text-muted-foreground">Detect unauthorized data transfers</p>
                  </div>
                </li>
                <li className="flex items-start gap-3">
                  <div className="bg-red-500/10 p-1 rounded-full mt-1">
                    <Shield className="h-4 w-4 text-red-500" />
                  </div>
                  <div>
                    <h4 className="font-medium">Real-time Alerts</h4>
                    <p className="text-sm text-muted-foreground">Get notified immediately of security threats</p>
                  </div>
                </li>
              </ul>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: 0.2 }}
              className="col-span-full lg:col-span-2 bg-card border border-border rounded-xl overflow-hidden"
            >
              <div className="p-6 border-b border-border">
                <h3 className="text-xl font-bold">Live Threat Detection</h3>
              </div>
              <div className="p-6">
                <div className="relative h-[400px]">
                  <ThreatVisualization />
                </div>
              </div>
            </motion.div>
          </div>
        </div>
      </section>

      <section className="py-20 bg-gradient-to-br from-primary/20 via-background to-background">
        <div className="container px-4 md:px-6 mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5 }}
            className="max-w-[800px] mx-auto text-center"
          >
            <h2 className="text-3xl md:text-4xl font-bold mb-4">Ready to gain insights into your network?</h2>
            <p className="text-muted-foreground mb-8 text-lg">
              Start monitoring your network traffic with precision and discover hidden patterns
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <Button asChild size="lg" className="px-8">
                <Link href="/sniffer">
                  Start Sniffing <ArrowRight className="ml-2 h-4 w-4" />
                </Link>
              </Button>
              <Button asChild variant="outline" size="lg">
                <Link href="/dashboard">View Dashboard</Link>
              </Button>
            </div>
          </motion.div>
        </div>
      </section>

      <footer className="py-12 border-t border-border bg-black/40">
        <div className="container px-4 md:px-6 mx-auto">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8 mb-12 max-w-6xl mx-auto">
            <div>
              <h3 className="font-bold mb-4">Product</h3>
              <ul className="space-y-2">
                <li>
                  <Link href="#" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                    Features
                  </Link>
                </li>
                <li>
                  <Link href="#" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                    Security
                  </Link>
                </li>
                <li>
                  <Link href="#" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                    Performance
                  </Link>
                </li>
                <li>
                  <Link href="#" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                    Integrations
                  </Link>
                </li>
              </ul>
            </div>
            <div>
              <h3 className="font-bold mb-4">Resources</h3>
              <ul className="space-y-2">
                <li>
                  <Link href="/documentation" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                    Documentation
                  </Link>
                </li>
                <li>
                  <Link href="#" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                    API Reference
                  </Link>
                </li>
                <li>
                  <Link href="#" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                    Guides
                  </Link>
                </li>
                <li>
                  <Link href="#" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                    Support
                  </Link>
                </li>
              </ul>
            </div>
            <div>
              <h3 className="font-bold mb-4">Company</h3>
              <ul className="space-y-2">
                <li>
                  <Link href="#" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                    About
                  </Link>
                </li>
                <li>
                  <Link href="#" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                    Blog
                  </Link>
                </li>
                <li>
                  <Link href="#" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                    Careers
                  </Link>
                </li>
                <li>
                  <Link href="#" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                    Contact
                  </Link>
                </li>
              </ul>
            </div>
            <div>
              <h3 className="font-bold mb-4">Legal</h3>
              <ul className="space-y-2">
                <li>
                  <Link href="#" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                    Privacy
                  </Link>
                </li>
                <li>
                  <Link href="#" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                    Terms
                  </Link>
                </li>
                <li>
                  <Link href="#" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                    Security
                  </Link>
                </li>
                <li>
                  <Link href="#" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                    Cookies
                  </Link>
                </li>
              </ul>
            </div>
          </div>
          <div className="flex flex-col md:flex-row justify-between items-center pt-8 border-t border-border max-w-6xl mx-auto">
            <div className="flex items-center gap-2 mb-4 md:mb-0">
              <Network className="h-5 w-5 text-primary" />
              <span className="font-semibold">PacketVigil</span>
            </div>
            <p className="text-sm text-muted-foreground">&copy; {new Date().getFullYear()} PacketVigil. All rights reserved.</p>
          </div>
        </div>
      </footer>
    </div>
  )
}

function EnhancedNetworkAnimation() {
  return (
    <div className="relative w-full h-full">
      <svg className="absolute inset-0 w-full h-full" viewBox="0 0 1000 500">
        <defs>
          <linearGradient id="gradient" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="hsl(var(--primary))" stopOpacity="0.7" />
            <stop offset="100%" stopColor="hsl(var(--primary))" stopOpacity="0.1" />
          </linearGradient>
          <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="15" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
          <filter id="nodeGlow" x="-100%" y="-100%" width="300%" height="300%">
            <feGaussianBlur stdDeviation="5" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
        </defs>

        {/* Grid lines */}
        <g stroke="rgba(255,255,255,0.1)" strokeWidth="0.5">
          {[...Array(6)].map((_, i) => (
            <line key={`h-${i}`} x1="0" y1={i * 100} x2="1000" y2={i * 100} />
          ))}
          {[...Array(11)].map((_, i) => (
            <line key={`v-${i}`} x1={i * 100} x2={i * 100} y1="0" y2="500" />
          ))}
        </g>

        <g className="nodes-and-links">
          {[...Array(25)].map((_, i) => {
            const row = Math.floor(i / 5);
            const col = i % 5;
            const x = 100 + col * 200;
            const y = 100 + row * 100;
            const isCenter = row === 2 && col === 2;
            const nodeSize = isCenter ? 30 : (i % 5 === 0 ? 12 : 8);

            return (
              <g key={i}>
                <motion.circle
                  cx={x}
                  cy={y}
                  r={nodeSize}
                  fill={isCenter ? "white" : "rgba(255,255,255,0.7)"}
                  filter={isCenter ? "url(#glow)" : "url(#nodeGlow)"}
                  initial={{ opacity: 0.2 }}
                  animate={{
                    opacity: isCenter ? [0.8, 1, 0.8] : [0.2, 0.7, 0.2],
                    scale: isCenter ? [1, 1.1, 1] : [1, 1.05, 1],
                  }}
                  transition={{
                    duration: isCenter ? 4 : 2 + (i % 3),
                    repeat: Number.POSITIVE_INFINITY,
                    delay: i * 0.1,
                    ease: "easeInOut",
                  }}
                />

                {col < 4 && (
                  <motion.line
                    x1={x}
                    y1={y}
                    x2={x + 200}
                    y2={y}
                    stroke="rgba(255,255,255,0.3)"
                    strokeWidth={isCenter || col === 1 || col === 2 ? 1 : 0.5}
                    initial={{ opacity: 0.1 }}
                    animate={{
                      opacity: [0.1, 0.4, 0.1],
                    }}
                    transition={{
                      duration: 3 + i % 2,
                      repeat: Number.POSITIVE_INFINITY,
                      delay: i * 0.2,
                      ease: "easeInOut",
                    }}
                  />
                )}

                {row < 4 && (
                  <motion.line
                    x1={x}
                    y1={y}
                    x2={x}
                    y2={y + 100}
                    stroke="rgba(255,255,255,0.3)"
                    strokeWidth={isCenter || row === 1 || row === 2 ? 1 : 0.5}
                    initial={{ opacity: 0.1 }}
                    animate={{
                      opacity: [0.1, 0.3, 0.1],
                    }}
                    transition={{
                      duration: 4 + i % 3,
                      repeat: Number.POSITIVE_INFINITY,
                      delay: i * 0.15,
                      ease: "easeInOut",
                    }}
                  />
                )}

                {(i === 0 || i === 4 || i === 20 || i === 24) && (
                  <motion.line
                    x1={x}
                    y1={y}
                    x2={500}
                    y2={250}
                    stroke="rgba(255,255,255,0.5)"
                    strokeWidth={1.5}
                    strokeDasharray="5,10"
                    initial={{ opacity: 0.1, pathLength: 0 }}
                    animate={{
                      opacity: [0.2, 0.6, 0.2],
                      pathLength: [0.3, 1, 0.3],
                    }}
                    transition={{
                      duration: 5,
                      repeat: Number.POSITIVE_INFINITY,
                      delay: i * 0.1,
                      ease: "easeInOut",
                    }}
                  />
                )}
              </g>
            );
          })}

          {[...Array(15)].map((_, i) => {
            const isHorizontal = i % 2 === 0;
            const startX = isHorizontal ? 100 + (i % 5) * 200 : 500;
            const startY = isHorizontal ? 250 : 100 + (i % 4) * 100;
            const endX = isHorizontal ? 900 : 500;
            const endY = isHorizontal ? 250 : 400;

            return (
              <motion.circle
                key={`packet-${i}`}
                r={4}
                fill="white"
                filter="url(#nodeGlow)"
                initial={{
                  x: startX,
                  y: startY,
                  opacity: 0,
                }}
                animate={{
                  x: [startX, endX, startX],
                  y: [startY, endY, startY],
                  opacity: [0, 1, 0],
                }}
                transition={{
                  duration: 4 + (i % 3),
                  repeat: Number.POSITIVE_INFINITY,
                  delay: i * 0.7,
                  ease: "easeInOut",
                }}
              />
            );
          })}
        </g>

        <g transform="translate(500, 250)">
          <motion.circle
            r={35}
            fill="white"
            filter="url(#glow)"
            initial={{ opacity: 0.7 }}
            animate={{
              opacity: [0.7, 1, 0.7],
              scale: [1, 1.1, 1],
            }}
            transition={{
              duration: 4,
              repeat: Number.POSITIVE_INFINITY,
              ease: "easeInOut",
            }}
          />

          {[...Array(3)].map((_, i) => (
            <motion.circle
              key={`ring-${i}`}
              r={50 + i * 25}
              fill="transparent"
              stroke="rgba(255,255,255,0.5)"
              strokeWidth={3 - i}
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{
                opacity: [0, 0.5 - (i * 0.15), 0],
                scale: [0.8, 1.5, 1.8],
              }}
              transition={{
                duration: 4,
                repeat: Number.POSITIVE_INFINITY,
                delay: i * 1.2,
                ease: "easeOut",
              }}
            />
          ))}

          <motion.circle
            r={80}
            fill="transparent"
            stroke="rgba(255,255,255,0.3)"
            strokeWidth="1"
            strokeDasharray="3,10"
            initial={{ opacity: 0.2 }}
            animate={{
              opacity: [0.2, 0.4, 0.2],
              rotate: [0, 360],
            }}
            transition={{
              duration: 30,
              repeat: Number.POSITIVE_INFINITY,
              ease: "linear",
            }}
          />
        </g>

        {[...Array(10)].map((_, i) => {
          const radius = 200 + (i * 20);
          const speed = 20 + (i * 5);
          const size = 2 + (i % 3);
          const angle = (i * 36) * (Math.PI / 180);
          const x = 500 + radius * Math.cos(angle);
          const y = 250 + radius * Math.sin(angle);

          return (
            <motion.circle
              key={`particle-${i}`}
              cx={x}
              cy={y}
              r={size}
              fill="white"
              opacity={0.6}
              animate={{
                rotate: [0, 360],
              }}
              style={{
                originX: 500,
                originY: 250,
              }}
              transition={{
                duration: speed,
                repeat: Number.POSITIVE_INFINITY,
                ease: "linear",
              }}
            />
          );
        })}
      </svg>
    </div>
  );
}

function ThreatVisualization() {
  return (
    <div className="w-full h-full">
      <svg className="w-full h-full" viewBox="0 0 800 400">
        <defs>
          <linearGradient id="threatGradient" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.7" />
            <stop offset="50%" stopColor="#8b5cf6" stopOpacity="0.7" />
            <stop offset="100%" stopColor="#ec4899" stopOpacity="0.7" />
          </linearGradient>
          <filter id="threatGlow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="5" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
        </defs>

        <g className="grid">
          {[...Array(9)].map((_, i) => (
            <line
              key={`h-${i}`}
              x1="0"
              y1={50 * i}
              x2="800"
              y2={50 * i}
              stroke="hsl(var(--border))"
              strokeWidth="0.5"
              strokeDasharray="2,4"
            />
          ))}
          {[...Array(17)].map((_, i) => (
            <line
              key={`v-${i}`}
              x1={50 * i}
              y1="0"
              x2={50 * i}
              y2="400"
              stroke="hsl(var(--border))"
              strokeWidth="0.5"
              strokeDasharray="2,4"
            />
          ))}
        </g>

        <g className="network-map">
          <motion.path
            d="M100,200 C150,150 200,180 250,150 S350,100 400,120 S500,150 550,130 S650,100 700,120"
            fill="none"
            stroke="url(#threatGradient)"
            strokeWidth="2"
            initial={{ pathLength: 0, opacity: 0 }}
            animate={{ pathLength: 1, opacity: 0.7 }}
            transition={{ duration: 2, ease: "easeInOut" }}
          />
          <motion.path
            d="M50,350 C100,320 150,330 200,300 S300,250 350,270 S450,250 500,270 S600,300 650,280 S700,250 750,230"
            fill="none"
            stroke="#ef4444"
            strokeWidth="2"
            initial={{ pathLength: 0, opacity: 0 }}
            animate={{ pathLength: 1, opacity: 0.7 }}
            transition={{ duration: 2, ease: "easeInOut", delay: 0.5 }}
          />

          {[
            { x: 100, y: 200, size: 8, color: "#3b82f6", threat: false },
            { x: 250, y: 150, size: 8, color: "#8b5cf6", threat: false },
            { x: 400, y: 120, size: 10, color: "#8b5cf6", threat: false },
            { x: 550, y: 130, size: 8, color: "#ec4899", threat: false },
            { x: 700, y: 120, size: 8, color: "#3b82f6", threat: false },
            { x: 50, y: 350, size: 8, color: "#ef4444", threat: true },
            { x: 200, y: 300, size: 8, color: "#ef4444", threat: true },
            { x: 350, y: 270, size: 10, color: "#ef4444", threat: true },
            { x: 500, y: 270, size: 8, color: "#ef4444", threat: true },
            { x: 650, y: 280, size: 8, color: "#ef4444", threat: true },
            { x: 750, y: 230, size: 8, color: "#ef4444", threat: true },
          ].map((node, i) => (
            <motion.circle
              key={`node-${i}`}
              cx={node.x}
              cy={node.y}
              r={node.size}
              fill={node.color}
              filter="url(#threatGlow)"
              initial={{ opacity: 0 }}
              animate={{
                opacity: 1,
                r: node.threat ? [node.size, node.size * 1.3, node.size] : node.size,
              }}
              transition={{
                duration: 0.5,
                delay: i * 0.1,
                repeat: node.threat ? Number.POSITIVE_INFINITY : 0,
                repeatDelay: 2,
              }}
            />
          ))}
          {[
            { x: 50, y: 350 },
            { x: 200, y: 300 },
            { x: 350, y: 270 },
            { x: 500, y: 270 },
            { x: 650, y: 280 },
            { x: 750, y: 230 },
          ].map((pos, i) => (
            <motion.g key={`threat-${i}`} transform={`translate(${pos.x}, ${pos.y})`}>
              <motion.circle
                r={20}
                fill="transparent"
                stroke="#ef4444"
                strokeWidth="1"
                initial={{ opacity: 0 }}
                animate={{
                  opacity: [0, 0.5, 0],
                  scale: [1, 2, 1],
                }}
                transition={{
                  duration: 3,
                  repeat: Number.POSITIVE_INFINITY,
                  delay: i * 0.5,
                  ease: "easeInOut",
                }}
              />
            </motion.g>
          ))}
        </g>

        <g transform="translate(650, 20)">
          <rect x="0" y="0" width="140" height="80" rx="4" fill="hsl(var(--card))" stroke="hsl(var(--border))" />
          <circle cx="15" cy="20" r="6" fill="#3b82f6" />
          <text x="30" y="24" fill="currentColor" fontSize="12">
            Safe Node
          </text>
          <circle cx="15" cy="45" r="6" fill="#ef4444" />
          <text x="30" y="49" fill="currentColor" fontSize="12">
            Threat Detected
          </text>
          <line x1="10" y1="65" x2="25" y2="65" stroke="#ef4444" strokeWidth="2" />
          <text x="30" y="69" fill="currentColor" fontSize="12">
            Malicious Traffic
          </text>
        </g>

        <g className="alerts">
          {[
            { x: 50, y: 350, text: "Port Scan" },
            { x: 350, y: 270, text: "Data Exfiltration" },
            { x: 650, y: 280, text: "Malware C2" },
          ].map((alert, i) => (
            <motion.g
              key={`alert-${i}`}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 1 + i * 0.5 }}
            >
              <line
                x1={alert.x}
                y1={alert.y}
                x2={alert.x + 50}
                y2={alert.y - 50}
                stroke="#ef4444"
                strokeWidth="1"
                strokeDasharray="3,3"
              />
              <rect
                x={alert.x + 50 - 5}
                y={alert.y - 50 - 20}
                width={alert.text.length * 7 + 10}
                height="20"
                rx="4"
                fill="#ef4444"
              />
              <text x={alert.x + 50} y={alert.y - 50 - 5} fill="white" fontSize="10" textAnchor="middle">
                {alert.text}
              </text>
            </motion.g>
          ))}
        </g>
      </svg>
    </div>
  )
}