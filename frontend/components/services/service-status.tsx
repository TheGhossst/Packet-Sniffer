import { useCallback, useEffect, useState } from "react";
import { Activity, Database, Server } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { LoadingSpinner } from "@/components/ui/loading-spinner";
import { ServiceStatus, ServicesState, fetchServicesStatus } from "@/lib/services";

export function ServiceStatusCards() {
  const [data, setData] = useState<ServicesState | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    try {
      setIsLoading(true);
      const servicesData = await fetchServicesStatus();
      setData(servicesData);
      setError(null);
    } catch (err) {
      setError("Failed to load service status");
      console.error("Error loading service status:", err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    const intervalId = setInterval(loadData, 30000);
    return () => clearInterval(intervalId);
  }, [loadData]);

  if (isLoading) {
    return <LoadingSpinner message="Loading service status..." />;
  }

  if (error) {
    return (
      <div className="p-4 text-center">
        <p className="text-red-500">{error}</p>
        <button
          onClick={loadData}
          className="mt-2 px-3 py-1 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 text-sm"
        >
          Retry
        </button>
      </div>
    );
  }

  if (!data || data.services.length === 0) {
    return (
      <div className="p-4 text-center">
        <p className="text-muted-foreground">No service status available</p>
      </div>
    );
  }

  return (
    <div className="col-span-3 grid gap-6 sm:grid-cols-1 md:grid-cols-3">
      {data.services.map((service) => (
        <ServiceStatusCard key={service.id} service={service} />
      ))}
    </div>
  );
}

interface ServiceStatusCardProps {
  service: ServiceStatus;
}

function ServiceStatusCard({ service }: ServiceStatusCardProps) {
  const getServiceIcon = (id: string) => {
    switch (id) {
      case "analysis-service":
        return <Server className="h-5 w-5" />;
      case "ipsum-feed":
        return <Database className="h-5 w-5" />;
      case "metrics-endpoint":
        return <Activity className="h-5 w-5" />;
      default:
        return <Server className="h-5 w-5" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "online":
        return "bg-green-500";
      case "degraded":
        return "bg-yellow-500";
      case "offline":
        return "bg-red-500";
      default:
        return "bg-gray-500";
    }
  };

  const getStatusText = (status: string) => {
    switch (status) {
      case "online":
        return "Online";
      case "degraded":
        return "Degraded";
      case "offline":
        return "Offline";
      default:
        return "Unknown";
    }
  };

  return (
    <Card className="col-span-1">
      <CardHeader className="flex flex-row items-center gap-2 pb-2">
        {getServiceIcon(service.id)}
        <div>
          <CardTitle className="text-base">{service.name}</CardTitle>
          <CardDescription>{service.description}</CardDescription>
        </div>
      </CardHeader>
      <CardContent>
        <div className="flex items-center gap-2 mt-0.5">
          <div className={`flex h-2 w-2 rounded-full ${getStatusColor(service.status)}`} />
          <span className="text-sm text-muted-foreground">{getStatusText(service.status)}</span>
        </div>
        <p className="text-xs text-muted-foreground mt-2">{service.statusMessage}</p>
      </CardContent>
    </Card>
  );
}