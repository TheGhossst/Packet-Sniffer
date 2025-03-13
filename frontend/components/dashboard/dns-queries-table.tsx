import React from 'react';

export default function DnsQueriesTable() {
  return (
    <div className="rounded-md border">
      <div className="p-6 flex flex-col items-center justify-center">
        <h3 className="text-lg font-medium mb-2">DNS Queries</h3>
        <p className="text-muted-foreground text-sm">Recent DNS queries will be displayed here.</p>
      </div>
    </div>
  );
}
