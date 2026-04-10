import { useState, useEffect } from "react";
import {
  Shield,
  Target,
  AlertTriangle,
  Link2,
  TrendingDown,
  TrendingUp,
  Radio,
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

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  info: "#6b7280",
};

const MOCK_TREND = [
  { date: "Mar 1", critical: 8, high: 12, medium: 18, low: 5 },
  { date: "Mar 8", critical: 6, high: 14, medium: 15, low: 8 },
  { date: "Mar 15", critical: 9, high: 11, medium: 20, low: 6 },
  { date: "Mar 22", critical: 5, high: 9, medium: 16, low: 4 },
  { date: "Mar 29", critical: 7, high: 13, medium: 12, low: 7 },
  { date: "Apr 5", critical: 4, high: 8, medium: 14, low: 3 },
  { date: "Apr 10", critical: 3, high: 6, medium: 10, low: 2 },
];

const MOCK_SEVERITY_DIST = [
  { name: "Critical", value: 3, color: "#ef4444" },
  { name: "High", value: 6, color: "#f97316" },
  { name: "Medium", value: 10, color: "#eab308" },
  { name: "Low", value: 2, color: "#3b82f6" },
];

const MOCK_AGENTS = [
  { name: "Prompt Injection", code: "PI-01", findings: 5, status: "idle" },
  { name: "Tool Poisoning", code: "TP-02", findings: 3, status: "idle" },
  { name: "Memory Poisoning", code: "MP-03", findings: 2, status: "idle" },
  { name: "Identity Spoof", code: "IS-04", findings: 4, status: "idle" },
  { name: "Context Window", code: "CW-05", findings: 1, status: "idle" },
  { name: "Cross-Agent Exfil", code: "CX-06", findings: 2, status: "idle" },
  { name: "Privilege Escalation", code: "PE-07", findings: 3, status: "idle" },
  { name: "Race Condition", code: "RC-08", findings: 0, status: "idle" },
  { name: "Supply Chain", code: "SC-09", findings: 1, status: "idle" },
  { name: "Model Extraction", code: "ME-10", findings: 0, status: "idle" },
  { name: "Persona Hijacking", code: "PH-11", findings: 2, status: "idle" },
  { name: "Memory Boundary", code: "MB-12", findings: 1, status: "idle" },
];

const MOCK_ALERTS = [
  {
    id: "1",
    type: "new_critical",
    title: "New Critical: Persona Drift Detected",
    time: "2 hours ago",
    severity: "critical",
  },
  {
    id: "2",
    type: "regression",
    title: "Regression: MCP Server Alpha — 3 new findings",
    time: "5 hours ago",
    severity: "high",
  },
  {
    id: "3",
    type: "scan_complete",
    title: "Scheduled scan completed: Target Bravo",
    time: "8 hours ago",
    severity: "info",
  },
];

export function DashboardPage() {
  const navigate = useNavigate();
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const interval = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(interval);
  }, []);

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
          value="21"
          change="-34%"
          trend="down"
          icon={AlertTriangle}
          subtitle="vs. last month"
        />
        <StatsCard
          title="Critical"
          value="3"
          change="-62%"
          trend="down"
          icon={Shield}
          subtitle="vs. last month"
          valueColor="text-red-500"
        />
        <StatsCard
          title="Active Targets"
          value="6"
          icon={Target}
          subtitle="4 healthy, 2 degraded"
        />
        <StatsCard
          title="Compound Chains"
          value="4"
          icon={Link2}
          subtitle="2 critical paths"
        />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Trend chart */}
        <Card className="lg:col-span-2">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Finding Trends — Last 6 Weeks
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={240}>
              <LineChart data={MOCK_TREND}>
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
                <Line type="monotone" dataKey="critical" stroke={SEVERITY_COLORS.critical} strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="high" stroke={SEVERITY_COLORS.high} strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="medium" stroke={SEVERITY_COLORS.medium} strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="low" stroke={SEVERITY_COLORS.low} strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
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
            <ResponsiveContainer width="100%" height={160}>
              <PieChart>
                <Pie
                  data={MOCK_SEVERITY_DIST}
                  cx="50%"
                  cy="50%"
                  innerRadius={40}
                  outerRadius={70}
                  dataKey="value"
                  strokeWidth={0}
                >
                  {MOCK_SEVERITY_DIST.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
            <div className="mt-2 grid grid-cols-2 gap-2">
              {MOCK_SEVERITY_DIST.map((s) => (
                <div key={s.name} className="flex items-center gap-2 text-xs">
                  <div className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: s.color }} />
                  <span className="text-muted-foreground">{s.name}</span>
                  <span className="ml-auto font-medium">{s.value}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Agents + Alerts row */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Agent grid */}
        <Card className="lg:col-span-2">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Attack Agents — 12 Online
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4">
              {MOCK_AGENTS.map((agent) => (
                <div
                  key={agent.code}
                  className="flex items-center gap-2 rounded-md border border-border bg-background p-2 text-xs"
                >
                  <div className="h-2 w-2 rounded-full bg-green-500" />
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
            <div className="space-y-3">
              {MOCK_ALERTS.map((alert) => (
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
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {[
              { target: "MCP Server Alpha", freq: "Daily", next: "Tomorrow 02:00 UTC", health: 85 },
              { target: "AI Agent Bravo", freq: "Weekly", next: "Mon 04:00 UTC", health: 62 },
              { target: "Pipeline Charlie", freq: "Daily", next: "Tomorrow 02:00 UTC", health: 91 },
            ].map((sched) => (
              <div key={sched.target} className="rounded-md border border-border bg-background p-3">
                <div className="flex items-center justify-between">
                  <p className="text-sm font-medium">{sched.target}</p>
                  <Badge variant="outline" className="text-xs">{sched.freq}</Badge>
                </div>
                <p className="mt-1 text-xs text-muted-foreground">Next: {sched.next}</p>
                <div className="mt-2 flex items-center gap-2">
                  <Progress value={sched.health} className="h-1.5 flex-1" />
                  <span className="text-xs text-muted-foreground">{sched.health}%</span>
                </div>
              </div>
            ))}
          </div>
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
