# Network Analysis Service Frontend

This is the frontend interface for the Network Analysis Service, built with [Next.js](https://nextjs.org) and bootstrapped with [`create-next-app`](https://nextjs.org/docs/app/api-reference/cli/create-next-app).

## Overview

The frontend provides a modern, responsive dashboard for monitoring network packets and security threats detected by the Analysis Service. It visualizes packet data, threat statuses, and system metrics in real-time.

## Features

- Real-time packet monitoring dashboard
- Threat visualization and statistics
- Detailed packet inspection with threat intelligence data
- Service performance metrics monitoring
- IP geolocation mapping
- Responsive design for all device sizes
- Dark/light mode support

## Getting Started

First, run the development server:

```bash
npm run dev
# or
yarn dev
# or
pnpm dev
# or
bun dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser to see the result.

You can start editing the page by modifying `app/page.tsx`. The page auto-updates as you edit the file.

This project uses [`next/font`](https://nextjs.org/docs/app/building-your-application/optimizing/fonts) to automatically optimize and load [Geist](https://vercel.com/font), a new font family for Vercel.

## Integration with Analysis Service

This frontend connects to the Analysis Service v2 to display:

- Latest captured packets and their metadata
- Threat intelligence results and safety status
- API integration metrics and error rates
- System performance statistics

## Configuration

The frontend can be configured through environment variables:

```
# .env.local
NEXT_PUBLIC_API_URL=http://localhost:3001
NEXT_PUBLIC_METRICS_URL=http://localhost:3002
```

## Learn More

To learn more about Next.js, take a look at the following resources:

- [Next.js Documentation](https://nextjs.org/docs) - learn about Next.js features and API.
- [Learn Next.js](https://nextjs.org/learn) - an interactive Next.js tutorial.

You can check out [the Next.js GitHub repository](https://github.com/vercel/next.js) - your feedback and contributions are welcome!

## Deployment

The easiest way to deploy your Next.js app is to use the [Vercel Platform](https://vercel.com/new?utm_medium=default-template&filter=next.js&utm_source=create-next-app&utm_campaign=create-next-app-readme) from the creators of Next.js.

Check out our [Next.js deployment documentation](https://nextjs.org/docs/app/building-your-application/deploying) for more details.
