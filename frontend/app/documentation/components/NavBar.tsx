"use client"

import Link from "next/link"

export default function NavBar(){
    return (
        <nav className="flex justify-between items-center h-16 bg-white text-black relative shadow-sm font-mono" >
            <div className="pl-8">
                <Link href="/" className="p-1">Home</Link>
                <Link href="/dashboard" className="p-1">Dashboard</Link>
            </div>
        </nav>
    )
}