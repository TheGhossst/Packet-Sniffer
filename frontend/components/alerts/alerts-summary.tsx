import { useCallback, useEffect, useState } from "react";
import { AlertTriangle, Clock, Database, Server } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { LoadingSpinner } from "@/components/ui/loading-spinner";
import { Alert, AlertsSummary, fetchAlerts, getRelativeTimeString } from "@/lib/alerts";

export function AlertsSummaryCards() {
  const [data, setData] = useState<AlertsSummary | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    try {
      setIsLoading(true);
      const alertsData = await fetchAlerts();
      setData(alertsData);
      setError(null);
    } catch (err) {
      setError("Failed to load alerts");
      console.error("Error loading alerts:", err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    // Set up a refresh interval (every 60 seconds)
    const intervalId = setInterval(loadData, 60000);
    return () => clearInterval(intervalId);
  }, [loadData]);

  if (isLoading) {
    return <LoadingSpinner message="Loading alerts..." />;
  }

  if (error) {
    return (
      <div className="p-6 text-center">
        <AlertTriangle className="h-10 w-10 text-orange-500 mx-auto mb-4" />
        <h3 className="text-xl font-semibold mb-2">Error Loading Alerts</h3>
        <p className="text-muted-foreground">{error}</p>
        <button
          onClick={loadData}
          className="mt-4 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
        >
          Retry
        </button>
      </div>
    );
  }

  if (!data || data.totalCount === 0) {
    return (
      <div className="p-6 text-center">
        <p className="text-muted-foreground">No alerts found</p>
      </div>
    );
  }

  const securityAlerts = data.alerts.filter(
    (alert) => alert.type === "security" && alert.status === "active"
  );
  const systemAlerts = data.alerts.filter(
    (alert) => alert.type === "system" && alert.status === "resolved"
  );

  return (
    <div className="grid gap-6 md:grid-cols-2">
      <ActiveAlertsCard alerts={securityAlerts} />
      <SystemNotificationsCard alerts={systemAlerts} />
    </div>
  );
}

interface AlertCardProps {
  alerts: Alert[];
}

function ActiveAlertsCard({ alerts }: AlertCardProps) {
  if (alerts.length === 0) {
    return (
      <Card className="col-span-2 md:col-span-1">
        <CardHeader>
          <CardTitle>Active Alerts</CardTitle>
          <CardDescription>Recent security and system alerts that require attention</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="p-6 text-center">
            <p className="text-muted-foreground">No active alerts at this time</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="col-span-2 md:col-span-1">
      <CardHeader>
        <CardTitle>Active Alerts</CardTitle>
        <CardDescription>Recent security and system alerts that require attention</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-6">
          {alerts.map((alert) => (
            <div key={alert.id} className="flex items-start gap-4">
              <div className={`p-2 rounded-full ${getAlertBgColor(alert.severity)}`}>
                <AlertTriangle className={`h-5 w-5 ${getAlertTextColor(alert.severity)}`} />
              </div>
              <div>
                <p className="font-medium">{alert.title}</p>
                <p className="text-sm text-muted-foreground">{alert.description}</p>
                <p className="text-xs text-muted-foreground mt-1">
                  {getRelativeTimeString(alert.timestamp)}
                </p>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function SystemNotificationsCard({ alerts }: AlertCardProps) {
  if (alerts.length === 0) {
    return (
      <Card className="col-span-2 md:col-span-1">
        <CardHeader>
          <CardTitle>System Notifications</CardTitle>
          <CardDescription>Important system events and maintenance information</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="p-6 text-center">
            <p className="text-muted-foreground">No system notifications at this time</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="col-span-2 md:col-span-1">
      <CardHeader>
        <CardTitle>System Notifications</CardTitle>
        <CardDescription>Important system events and maintenance information</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-6">
          {alerts.map((alert) => (
            <div key={alert.id} className="flex items-start gap-4">
              <div className="p-2 rounded-full bg-blue-100 dark:bg-blue-900/20">
                {getIconForSystemAlert(alert.title)}
              </div>
              <div>
                <p className="font-medium">{alert.title}</p>
                <p className="text-sm text-muted-foreground">{alert.description}</p>
                <p className="text-xs text-muted-foreground mt-1">
                  {getRelativeTimeString(alert.timestamp)}
                </p>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

// Helper functions
function getAlertBgColor(severity: string): string {
  switch (severity) {
    case "high":
      return "bg-red-100 dark:bg-red-900/20";
    case "medium":
      return "bg-amber-100 dark:bg-amber-900/20";
    case "low":
      return "bg-yellow-100 dark:bg-yellow-900/20";
    default:
      return "bg-blue-100 dark:bg-blue-900/20";
  }
}

function getAlertTextColor(severity: string): string {
  switch (severity) {
    case "high":
      return "text-red-600 dark:text-red-500";
    case "medium":
      return "text-amber-600 dark:text-amber-500";
    case "low":
      return "text-yellow-600 dark:text-yellow-500";
    default:
      return "text-blue-600 dark:text-blue-500";
  }
}

function getIconForSystemAlert(title: string) {
  if (title.includes("maintenance")) {
    return <Clock className="h-5 w-5 text-blue-600 dark:text-blue-500" />;
  } else if (title.includes("IPSUM") || title.includes("feed")) {
    return <Database className="h-5 w-5 text-green-600 dark:text-green-500" />;
  } else {
    return <Server className="h-5 w-5 text-blue-600 dark:text-blue-500" />;
  }
}
