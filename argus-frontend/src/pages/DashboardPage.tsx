import { useState, useEffect } from "react";
import {
  Shield,
  Target,
  AlertTriangle,
  Link2,
  TrendingDown,
  TrendingUp,
  Radio,
  Loader2,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { useNavigate } from "react-router-dom";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import { getDashboardStats, getAgentStatus, getAlerts, getScheduledScans } from "@/api/client";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  info: "#6b7280",
};

export function DashboardPage() {
  const navigate = useNavigate();
  const [time, setTime] = useState(new Date());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState<Awaited<ReturnType<typeof getDashboardStats>> | null>(null);
  const [agents, setAgents] = useState<{ code: string; name: string; findings: number; status: string }[]>([]);
  const [alerts, setAlerts] = useState<{ id: string; type: string; title: string; time: string; severity: string }[]>([]);
  const [schedules, setSchedules] = useState<Record<string, unknown>[]>([]);

  useEffect(() => {
    const interval = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        setLoading(true);
        const [s, a, al, sc] = await Promise.all([
          getDashboardStats(),
          getAgentStatus(),
          getAlerts(10),
          getScheduledScans(),
        ]);
        if (cancelled) return;
        setStats(s);
        setAgents(a.agents);
        setAlerts(al.alerts);
        setSchedules(sc.schedules);
        setError(null);
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load dashboard");
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => { cancelled = true; };
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-center">
        <AlertTriangle className="h-8 w-8 text-red-500" />
        <p className="mt-2 text-sm text-muted-foreground">{error}</p>
        <Button variant="outline" size="sm" className="mt-4" onClick={() => window.location.reload()}>
          Retry
        </Button>
      </div>
    );
  }

  const severityDist = stats?.severity_distribution ?? [];
  const trend = stats?.trend ?? [];

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Dashboard</h2>
          <p className="text-sm text-muted-foreground">
            Continuous AI security monitoring • {time.toLocaleString()}
          </p>
        </div>
        <Button onClick={() => navigate("/scan/live")} className="gap-2">
          <Radio className="h-4 w-4" />
          New Scan
        </Button>
      </div>

      {/* Stats cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatsCard
          title="Total Findings"
          value={String(stats?.total_findings ?? 0)}
          icon={AlertTriangle}
          subtitle={`${stats?.completed_scans ?? 0} scans completed`}
        />
        <StatsCard
          title="Critical"
          value={String(stats?.critical ?? 0)}
          icon={Shield}
          subtitle={`${stats?.high ?? 0} high severity`}
          valueColor="text-red-500"
        />
        <StatsCard
          title="Active Targets"
          value={String(stats?.active_targets ?? 0)}
          icon={Target}
          subtitle={`${stats?.total_scans ?? 0} total scans`}
        />
        <StatsCard
          title="Compound Chains"
          value={String(stats?.compound_chains ?? 0)}
          icon={Link2}
          subtitle="multi-step attack paths"
        />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Trend chart */}
        <Card className="lg:col-span-2">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Finding Trends — Recent Scans
            </CardTitle>
          </CardHeader>
          <CardContent>
            {trend.length > 0 ? (
              <ResponsiveContainer width="100%" height={240}>
                <LineChart data={trend}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(0 0% 14.9%)" />
                  <XAxis dataKey="date" tick={{ fill: "#a1a1aa", fontSize: 12 }} />
                  <YAxis tick={{ fill: "#a1a1aa", fontSize: 12 }} />
                  <Tooltip
                    contentStyle={{
                      background: "hsl(0 0% 5.5%)",
                      border: "1px solid hsl(0 0% 14.9%)",
                      borderRadius: "6px",
                    }}
                  />
                  <Line type="monotone" dataKey="findings" stroke={SEVERITY_COLORS.critical} strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <p className="py-16 text-center text-sm text-muted-foreground">No scan data yet — run a scan to see trends</p>
            )}
          </CardContent>
        </Card>

        {/* Severity distribution */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Severity Distribution
            </CardTitle>
          </CardHeader>
          <CardContent>
            {severityDist.some((s) => s.value > 0) ? (
              <>
                <ResponsiveContainer width="100%" height={160}>
                  <PieChart>
                    <Pie
                      data={severityDist}
                      cx="50%"
                      cy="50%"
                      innerRadius={40}
                      outerRadius={70}
                      dataKey="value"
                      strokeWidth={0}
                    >
                      {severityDist.map((entry, i) => (
                        <Cell key={i} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
                <div className="mt-2 grid grid-cols-2 gap-2">
                  {severityDist.map((s) => (
                    <div key={s.name} className="flex items-center gap-2 text-xs">
                      <div className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: s.color }} />
                      <span className="text-muted-foreground">{s.name}</span>
                      <span className="ml-auto font-medium">{s.value}</span>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <p className="py-16 text-center text-sm text-muted-foreground">No findings yet</p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Agents + Alerts row */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Agent grid */}
        <Card className="lg:col-span-2">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Attack Agents — {agents.length} Online
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4">
              {agents.map((agent) => (
                <div
                  key={agent.code}
                  className="flex items-center gap-2 rounded-md border border-border bg-background p-2 text-xs"
                >
                  <div className={`h-2 w-2 rounded-full ${agent.status === "running" ? "bg-blue-500 animate-pulse" : agent.status === "error" ? "bg-red-500" : "bg-green-500"}`} />
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-medium">{agent.code}</p>
                    <p className="truncate text-muted-foreground">{agent.name}</p>
                  </div>
                  {agent.findings > 0 && (
                    <Badge variant="secondary" className="text-xs">
                      {agent.findings}
                    </Badge>
                  )}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Alert feed */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Recent Alerts
            </CardTitle>
          </CardHeader>
          <CardContent>
            {alerts.length > 0 ? (
              <div className="space-y-3">
                {alerts.map((alert) => (
                  <div key={alert.id} className="flex gap-3 rounded-md border border-border bg-background p-3">
                    <div
                      className="mt-0.5 h-2 w-2 rounded-full"
                      style={{
                        backgroundColor: SEVERITY_COLORS[alert.severity] || "#6b7280",
                      }}
                    />
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-medium">{alert.title}</p>
                      <p className="text-xs text-muted-foreground">{alert.time}</p>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="py-8 text-center text-sm text-muted-foreground">No alerts — system is quiet</p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Scheduled scans */}
      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Scheduled Scans
            </CardTitle>
            <Button variant="outline" size="sm" onClick={() => navigate("/platform/settings")}>
              Configure
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {schedules.length > 0 ? (
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {schedules.map((sched, i) => (
                <div key={i} className="rounded-md border border-border bg-background p-3">
                  <p className="text-sm font-medium">{String(sched.target || sched.name || `Schedule ${i + 1}`)}</p>
                  <p className="mt-1 text-xs text-muted-foreground">
                    {String(sched.frequency || sched.freq || "")}
                  </p>
                </div>
              ))}
            </div>
          ) : (
            <p className="py-6 text-center text-sm text-muted-foreground">
              No scheduled scans configured — set up recurring scans in Settings
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function StatsCard({
  title,
  value,
  change,
  trend,
  icon: Icon,
  subtitle,
  valueColor,
}: {
  title: string;
  value: string;
  change?: string;
  trend?: "up" | "down";
  icon: React.ElementType;
  subtitle?: string;
  valueColor?: string;
}) {
  return (
    <Card>
      <CardContent className="p-4">
        <div className="flex items-center justify-between">
          <p className="text-sm text-muted-foreground">{title}</p>
          <Icon className="h-4 w-4 text-muted-foreground" />
        </div>
        <div className="mt-2 flex items-end gap-2">
          <p className={`text-2xl font-bold ${valueColor || ""}`}>{value}</p>
          {change && (
            <span className={`flex items-center text-xs ${trend === "down" ? "text-green-500" : "text-red-500"}`}>
              {trend === "down" ? <TrendingDown className="mr-0.5 h-3 w-3" /> : <TrendingUp className="mr-0.5 h-3 w-3" />}
              {change}
            </span>
          )}
        </div>
        {subtitle && (
          <p className="mt-1 text-xs text-muted-foreground">{subtitle}</p>
        )}
      </CardContent>
    </Card>
  );
}
