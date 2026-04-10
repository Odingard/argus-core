import {
  Gauge,
  Cpu,
  HardDrive,
  Clock,
  CheckCircle,
  AlertTriangle,
  XCircle,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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

const MOCK_METRICS = [
  { time: "00:00", scans: 2, findings: 8, latency: 120 },
  { time: "04:00", scans: 1, findings: 3, latency: 95 },
  { time: "08:00", scans: 3, findings: 12, latency: 145 },
  { time: "12:00", scans: 4, findings: 15, latency: 180 },
  { time: "16:00", scans: 2, findings: 7, latency: 110 },
  { time: "20:00", scans: 3, findings: 9, latency: 130 },
];

const MOCK_AGENTS_HEALTH = [
  { code: "PI-01", name: "Prompt Injection", status: "healthy", uptime: "99.9%", lastRun: "2h ago", avgDuration: "45s" },
  { code: "TP-02", name: "Tool Poisoning", status: "healthy", uptime: "99.8%", lastRun: "2h ago", avgDuration: "38s" },
  { code: "MP-03", name: "Memory Poisoning", status: "healthy", uptime: "99.9%", lastRun: "2h ago", avgDuration: "52s" },
  { code: "IS-04", name: "Identity Spoof", status: "healthy", uptime: "99.7%", lastRun: "2h ago", avgDuration: "30s" },
  { code: "CW-05", name: "Context Window", status: "degraded", uptime: "97.2%", lastRun: "2h ago", avgDuration: "120s" },
  { code: "CX-06", name: "Cross-Agent Exfil", status: "healthy", uptime: "99.5%", lastRun: "2h ago", avgDuration: "41s" },
  { code: "PE-07", name: "Privilege Escalation", status: "healthy", uptime: "99.8%", lastRun: "2h ago", avgDuration: "55s" },
  { code: "RC-08", name: "Race Condition", status: "healthy", uptime: "99.6%", lastRun: "3h ago", avgDuration: "65s" },
  { code: "SC-09", name: "Supply Chain", status: "healthy", uptime: "99.9%", lastRun: "3h ago", avgDuration: "28s" },
  { code: "ME-10", name: "Model Extraction", status: "healthy", uptime: "99.4%", lastRun: "2h ago", avgDuration: "48s" },
  { code: "PH-11", name: "Persona Hijacking", status: "healthy", uptime: "99.8%", lastRun: "1h ago", avgDuration: "90s" },
  { code: "MB-12", name: "Memory Boundary", status: "healthy", uptime: "99.7%", lastRun: "1h ago", avgDuration: "85s" },
];

const STATUS_CONFIG: Record<string, { icon: React.ElementType; color: string }> = {
  healthy: { icon: CheckCircle, color: "text-green-400" },
  degraded: { icon: AlertTriangle, color: "text-yellow-400" },
  offline: { icon: XCircle, color: "text-red-400" },
};

export function MonitoringPage() {
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
              <p className="text-lg font-bold text-green-400">Operational</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-3 p-4">
            <Cpu className="h-5 w-5 text-muted-foreground" />
            <div>
              <p className="text-sm text-muted-foreground">CPU Usage</p>
              <p className="text-lg font-bold">23%</p>
              <Progress value={23} className="mt-1 h-1" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-3 p-4">
            <HardDrive className="h-5 w-5 text-muted-foreground" />
            <div>
              <p className="text-sm text-muted-foreground">Memory</p>
              <p className="text-lg font-bold">512 MB</p>
              <Progress value={41} className="mt-1 h-1" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-3 p-4">
            <Clock className="h-5 w-5 text-muted-foreground" />
            <div>
              <p className="text-sm text-muted-foreground">Uptime</p>
              <p className="text-lg font-bold">14d 7h 23m</p>
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
            <LineChart data={MOCK_METRICS}>
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
            Agent Health — 12 Agents
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {MOCK_AGENTS_HEALTH.map((agent) => {
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
                      <span>Uptime: {agent.uptime}</span>
                      <span>Avg: {agent.avgDuration}</span>
                      <span>Last: {agent.lastRun}</span>
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
