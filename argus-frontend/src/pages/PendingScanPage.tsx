import { useState, useEffect } from "react";
import { Clock, Play, Trash2, ArrowUpDown, Loader2, AlertTriangle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { getPendingScans, getScheduledScans } from "@/api/client";

interface PendingScan {
  id: string;
  target: string;
  mode: string;
  scheduled: string;
  priority: string;
  agents: number;
}

interface Schedule {
  target: string;
  freq: string;
  nextRun: string;
  enabled: boolean;
}

export function PendingScanPage() {
  const [pending, setPending] = useState<PendingScan[]>([]);
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        setLoading(true);
        const [pData, sData] = await Promise.all([getPendingScans(), getScheduledScans()]);
        if (cancelled) return;
        setPending(
          (pData.scans || []).map((s: Record<string, unknown>) => ({
            id: String(s.id ?? ""),
            target: String(s.target ?? s.target_name ?? ""),
            mode: String(s.mode ?? s.scan_mode ?? "Full Scan"),
            scheduled: String(s.scheduled ?? s.scheduled_at ?? ""),
            priority: String(s.priority ?? "normal"),
            agents: Number(s.agents ?? s.agent_count ?? 12),
          }))
        );
        setSchedules(
          (sData.schedules || []).map((s: Record<string, unknown>) => ({
            target: String(s.target ?? s.target_name ?? ""),
            freq: String(s.frequency ?? s.freq ?? ""),
            nextRun: String(s.next_run ?? ""),
            enabled: Boolean(s.enabled ?? true),
          }))
        );
        setError(null);
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load");
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => { cancelled = true; };
  }, []);

  if (loading) {
    return (<div className="flex items-center justify-center py-20"><Loader2 className="h-8 w-8 animate-spin text-primary" /></div>);
  }
  if (error) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-center">
        <AlertTriangle className="h-8 w-8 text-red-500" />
        <p className="mt-2 text-sm text-muted-foreground">{error}</p>
        <Button variant="outline" size="sm" className="mt-4" onClick={() => window.location.reload()}>Retry</Button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Pending Scans</h2>
          <p className="text-sm text-muted-foreground">
            Queued and scheduled scans waiting to execute
          </p>
        </div>
        <Badge variant="secondary">{pending.length} in queue</Badge>
      </div>

      {pending.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Clock className="h-12 w-12 text-muted-foreground/30" />
            <p className="mt-4 text-sm text-muted-foreground">No pending scans</p>
            <p className="text-xs text-muted-foreground/60">
              Schedule a scan or launch one from the Live Scan page
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {pending.map((scan) => (
            <Card key={scan.id}>
              <CardContent className="flex items-center gap-4 p-4">
                <div className="flex h-10 w-10 items-center justify-center rounded-md bg-primary/10">
                  <Clock className="h-5 w-5 text-primary" />
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <p className="font-medium">{scan.target}</p>
                    <Badge variant="outline" className="text-xs">
                      {scan.mode}
                    </Badge>
                    {scan.priority === "high" && (
                      <Badge className="bg-orange-600 text-xs">High Priority</Badge>
                    )}
                  </div>
                  <p className="text-sm text-muted-foreground">
                    Scheduled: {scan.scheduled} • {scan.agents} agents
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <Button variant="outline" size="sm" className="gap-1">
                    <ArrowUpDown className="h-3 w-3" />
                    Reorder
                  </Button>
                  <Button size="sm" className="gap-1">
                    <Play className="h-3 w-3" />
                    Run Now
                  </Button>
                  <Button variant="ghost" size="sm" className="text-red-400 hover:text-red-300">
                    <Trash2 className="h-3 w-3" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Scheduled recurring scans */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium text-muted-foreground">
            Recurring Schedules
          </CardTitle>
        </CardHeader>
        <CardContent>
          {schedules.length === 0 ? (
            <p className="text-sm text-muted-foreground">No recurring schedules configured</p>
          ) : (
          <div className="space-y-3">
            {schedules.map((sched) => (
              <div
                key={sched.target}
                className="flex items-center justify-between rounded-md border border-border p-3"
              >
                <div>
                  <p className="text-sm font-medium">{sched.target}</p>
                  <p className="text-xs text-muted-foreground">
                    {sched.freq} • Next: {sched.nextRun}
                  </p>
                </div>
                <Badge variant={sched.enabled ? "default" : "secondary"}>
                  {sched.enabled ? "Active" : "Paused"}
                </Badge>
              </div>
            ))}
          </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
