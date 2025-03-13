import React from 'react';

export default function PacketTable() {
  return (
    <div className="rounded-md border">
      <div className="p-6 flex flex-col items-center justify-center">
        <h3 className="text-lg font-medium mb-2">Packet Information</h3>
        <p className="text-muted-foreground text-sm">Recent network packets will be displayed here.</p>
      </div>
    </div>
  );
}
