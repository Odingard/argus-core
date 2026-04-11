import { useState, useEffect } from "react";
import {
  Gauge,
  Cpu,
  HardDrive,
  Clock,
  CheckCircle,
  AlertTriangle,
  XCircle,
  Loader2,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { getMonitoringMetrics, getAgentStatus } from "@/api/client";

const STATUS_CONFIG: Record<string, { icon: React.ElementType; color: string }> = {
  healthy: { icon: CheckCircle, color: "text-green-400" },
  degraded: { icon: AlertTriangle, color: "text-yellow-400" },
  offline: { icon: XCircle, color: "text-red-400" },
};

export function MonitoringPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [platformStatus, setPlatformStatus] = useState("operational");
  const [system, setSystem] = useState<Record<string, unknown>>({});
  const [agentsHealth, setAgentsHealth] = useState<{ code: string; name: string; status: string; last_run: string | null; avg_duration: string }[]>([]);
  const [metrics] = useState([
    { time: "00:00", scans: 0, findings: 0 },
    { time: "04:00", scans: 0, findings: 0 },
    { time: "08:00", scans: 0, findings: 0 },
    { time: "12:00", scans: 0, findings: 0 },
    { time: "16:00", scans: 0, findings: 0 },
    { time: "20:00", scans: 0, findings: 0 },
  ]);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        setLoading(true);
        const [mon, agents] = await Promise.all([getMonitoringMetrics(), getAgentStatus()]);
        if (cancelled) return;
        setPlatformStatus(mon.platform_status ?? "operational");
        setSystem(mon.system ?? {});
        setAgentsHealth(
          (mon.agents_health ?? agents.agents).map((a: Record<string, unknown>) => ({
            code: String(a.code ?? ""),
            name: String(a.name ?? ""),
            status: String(a.status ?? "healthy"),
            last_run: a.last_run ? String(a.last_run) : null,
            avg_duration: String(a.avg_duration ?? "N/A"),
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

  const cpuPct = Number(system.cpu_percent ?? 0);
  const memMb = Number(system.memory_mb ?? 0);
  const memPct = Number(system.memory_percent ?? 0);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Platform Monitoring</h2>
        <p className="text-sm text-muted-foreground">
          ARGUS platform health, agent status, and performance metrics
        </p>
      </div>

      {/* System stats */}
      <div className="grid grid-cols-4 gap-4">
        <Card>
          <CardContent className="flex items-center gap-3 p-4">
            <Gauge className="h-5 w-5 text-green-400" />
            <div>
              <p className="text-sm text-muted-foreground">Platform Status</p>
              <p className="text-lg font-bold text-green-400 capitalize">{platformStatus}</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-3 p-4">
            <Cpu className="h-5 w-5 text-muted-foreground" />
            <div>
              <p className="text-sm text-muted-foreground">CPU Usage</p>
              <p className="text-lg font-bold">{cpuPct}%</p>
              <Progress value={cpuPct} className="mt-1 h-1" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-3 p-4">
            <HardDrive className="h-5 w-5 text-muted-foreground" />
            <div>
              <p className="text-sm text-muted-foreground">Memory</p>
              <p className="text-lg font-bold">{memMb} MB</p>
              <Progress value={memPct} className="mt-1 h-1" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-3 p-4">
            <Clock className="h-5 w-5 text-muted-foreground" />
            <div>
              <p className="text-sm text-muted-foreground">Uptime</p>
              <p className="text-lg font-bold">{String(system.uptime ?? "N/A")}</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Activity chart */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">
            24-Hour Activity
          </CardTitle>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={metrics}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(0 0% 14.9%)" />
              <XAxis dataKey="time" tick={{ fill: "#a1a1aa", fontSize: 12 }} />
              <YAxis tick={{ fill: "#a1a1aa", fontSize: 12 }} />
              <Tooltip
                contentStyle={{
                  background: "hsl(0 0% 5.5%)",
                  border: "1px solid hsl(0 0% 14.9%)",
                  borderRadius: "6px",
                }}
              />
              <Line type="monotone" dataKey="scans" stroke="#22c55e" strokeWidth={2} dot={false} name="Scans" />
              <Line type="monotone" dataKey="findings" stroke="#ef4444" strokeWidth={2} dot={false} name="Findings" />
            </LineChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      {/* Agent health grid */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">
            Agent Health — {agentsHealth.length} Agents
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {agentsHealth.map((agent) => {
              const config = STATUS_CONFIG[agent.status] || STATUS_CONFIG.healthy;
              const StatusIcon = config.icon;
              return (
                <div
                  key={agent.code}
                  className="flex items-center gap-3 rounded-md border border-border p-3"
                >
                  <StatusIcon className={`h-4 w-4 ${config.color}`} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm font-bold">{agent.code}</span>
                      <span className="truncate text-xs text-muted-foreground">{agent.name}</span>
                    </div>
                    <div className="flex items-center gap-3 text-xs text-muted-foreground">
                      <span>Avg: {agent.avg_duration}</span>
                      <span>Last: {agent.last_run ?? "Never"}</span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
