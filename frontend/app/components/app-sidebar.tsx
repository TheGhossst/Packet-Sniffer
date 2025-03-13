"use client"

import { usePathname } from "next/navigation"
import Link from "next/link"
import { BarChart3, Home, Network } from "lucide-react"
import {
    Sidebar,
    SidebarContent,
    SidebarFooter,
    SidebarHeader,
    SidebarMenu,
    SidebarMenuButton,
    SidebarMenuItem,
    SidebarSeparator,
} from "@/components/ui/sidebar"

export function AppSidebar() {
    const pathname = usePathname()

    const routes = [
        { name: "Home", path: "/", icon: Home },
        { name: "Dashboard", path: "/dashboard", icon: BarChart3 },
        { name: "Sniffer", path: "/sniffer", icon: Network },
    ]

    return (
        <Sidebar>
            <SidebarHeader className="flex items-center justify-between">
                <Link href="/" className="flex items-center gap-2 px-4">
                    <Network className="h-6 w-6 text-primary" />
                    <span className="font-bold text-xl">PacketVigil</span>
                </Link>
            </SidebarHeader>
            <SidebarSeparator />
            <SidebarContent>
                <SidebarMenu>
                    {routes.map((route) => (
                        <SidebarMenuItem key={route.path}>
                            <SidebarMenuButton asChild isActive={pathname === route.path} tooltip={route.name}>
                                <Link href={route.path}>
                                    <route.icon className="h-5 w-5" />
                                    <span>{route.name}</span>
                                </Link>
                            </SidebarMenuButton>
                        </SidebarMenuItem>
                    ))}
                </SidebarMenu>
            </SidebarContent>
            <SidebarFooter className="p-4">
                <div className="text-xs text-muted-foreground text-center">PacketVigil v1.0</div>
            </SidebarFooter>
        </Sidebar>
    )
}