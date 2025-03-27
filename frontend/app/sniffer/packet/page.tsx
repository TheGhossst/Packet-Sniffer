import { redirect } from 'next/navigation';

export default function PacketIndexPage() {
  // Redirect to the sniffer page since we need a specific packet ID
  redirect('/sniffer');
} 