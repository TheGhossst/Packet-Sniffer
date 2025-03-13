import { NextResponse } from 'next/server';

/**
 * API route to proxy requests to the Prometheus metrics endpoint
 * This avoids CORS issues when fetching from the frontend
 */
export async function GET() {
  try {
    const response = await fetch('http://localhost:9090/metrics', {
      headers: {
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache'
      },
      signal: AbortSignal.timeout(5000)
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch metrics: ${response.statusText}`);
    }

    const text = await response.text();
    
    return new NextResponse(text, {
      status: 200,
      headers: {
        'Content-Type': 'text/plain',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
      }
    });
  } catch (error) {
    console.error('Error proxying metrics request:', error);
    
    return new NextResponse(
      JSON.stringify({ error: 'Failed to fetch metrics from Prometheus endpoint' }), 
      { 
        status: 500,
        headers: {
          'Content-Type': 'application/json'
        }
      }
    );
  }
}