import { NextResponse } from 'next/server';

/**
 * API route to fetch metrics from the Prometheus server
 * This acts as a proxy to avoid CORS issues on the frontend
 */
export async function GET() {
  try {
    const response = await fetch('http://localhost:9090/metrics', {
      headers: {
        'Accept': 'text/plain',
        'Cache-Control': 'no-cache'
      },
      next: { revalidate: 0 } // Disable caching
    });

    if (!response.ok) {
      throw new Error(`Error fetching metrics: ${response.status} ${response.statusText}`);
    }

    const text = await response.text();
    return new NextResponse(text, {
      headers: {
        'Content-Type': 'text/plain',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
      }
    });
  } catch (error) {
    console.error('Error proxying metrics:', error);
    return new NextResponse(
      JSON.stringify({
        error: 'Failed to fetch metrics',
        message: error instanceof Error ? error.message : 'Unknown error'
      }),
      {
        status: 500,
        headers: {
          'Content-Type': 'application/json'
        }
      }
    );
  }
}