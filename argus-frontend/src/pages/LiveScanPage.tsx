import { useState } from "react";
import {
  Radio,
  Play,
  Square,
  Pause,
  AlertTriangle,
  CheckCircle,
  Clock,
  Loader2,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

interface AgentStatus {
  code: string;
  name: string;
  status: "idle" | "running" | "completed" | "error";
  progress: number;
  findings: number;
  techniques: number;
  currentTechnique?: string;
}

const INITIAL_AGENTS: AgentStatus[] = [
  { code: "PI-01", name: "Prompt Injection Hunter", status: "idle", progress: 0, findings: 0, techniques: 7 },
  { code: "TP-02", name: "Tool Poisoning Agent", status: "idle", progress: 0, findings: 0, techniques: 5 },
  { code: "MP-03", name: "Memory Poisoning Agent", status: "idle", progress: 0, findings: 0, techniques: 5 },
  { code: "IS-04", name: "Identity Spoof Agent", status: "idle", progress: 0, findings: 0, techniques: 5 },
  { code: "CW-05", name: "Context Window Agent", status: "idle", progress: 0, findings: 0, techniques: 7 },
  { code: "CX-06", name: "Cross-Agent Exfil Agent", status: "idle", progress: 0, findings: 0, techniques: 5 },
  { code: "PE-07", name: "Privilege Escalation Agent", status: "idle", progress: 0, findings: 0, techniques: 6 },
  { code: "RC-08", name: "Race Condition Agent", status: "idle", progress: 0, findings: 0, techniques: 5 },
  { code: "SC-09", name: "Supply Chain Agent", status: "idle", progress: 0, findings: 0, techniques: 4 },
  { code: "ME-10", name: "Model Extraction Agent", status: "idle", progress: 0, findings: 0, techniques: 6 },
  { code: "PH-11", name: "Persona Hijacking Agent", status: "idle", progress: 0, findings: 0, techniques: 5 },
  { code: "MB-12", name: "Memory Boundary Collapse", status: "idle", progress: 0, findings: 0, techniques: 5 },
];

export function LiveScanPage() {
  const [agents, setAgents] = useState<AgentStatus[]>(INITIAL_AGENTS);
  const [scanRunning, setScanRunning] = useState(false);
  const [targetUrl, setTargetUrl] = useState("");
  const [scanMode, setScanMode] = useState("full");

  const startScan = () => {
    if (!targetUrl) return;
    setScanRunning(true);
    // Simulate agent progression
    let step = 0;
    const interval = setInterval(() => {
      step++;
      setAgents((prev) =>
        prev.map((a, i) => {
          const delay = i * 3;
          if (step < delay) return a;
          const elapsed = step - delay;
          const progress = Math.min(elapsed * 8, 100);
          const findings = progress > 50 ? Math.floor(Math.random() * 4) : 0;
          return {
            ...a,
            status: progress >= 100 ? "completed" : "running",
            progress,
            findings,
            currentTechnique: progress < 100 ? `Technique ${Math.ceil(elapsed / 3)}/${a.techniques}` : undefined,
          };
        })
      );
      if (step > 60) {
        clearInterval(interval);
        setScanRunning(false);
      }
    }, 500);
  };

  const stopScan = () => {
    setScanRunning(false);
    setAgents((prev) =>
      prev.map((a) => ({
        ...a,
        status: a.status === "running" ? "idle" : a.status,
      }))
    );
  };

  const totalFindings = agents.reduce((sum, a) => sum + a.findings, 0);
  const completed = agents.filter((a) => a.status === "completed").length;
  const running = agents.filter((a) => a.status === "running").length;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Live Scan</h2>
          <p className="text-sm text-muted-foreground">
            Deploy all 12 agents against a target simultaneously
          </p>
        </div>
        {scanRunning && (
          <Badge variant="outline" className="gap-2 text-green-400 border-green-400/50">
            <Radio className="h-3 w-3 animate-pulse" />
            Scan Active
          </Badge>
        )}
      </div>

      {/* Scan configuration */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium text-muted-foreground">
            Scan Configuration
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex gap-4">
            <div className="flex-1">
              <Label className="text-xs">Target URL</Label>
              <Input
                placeholder="https://target-mcp-server.example.com or http://localhost:9999"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                disabled={scanRunning}
                className="mt-1"
              />
            </div>
            <div className="w-48">
              <Label className="text-xs">Scan Mode</Label>
              <Select value={scanMode} onValueChange={setScanMode} disabled={scanRunning}>
                <SelectTrigger className="mt-1">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="full">Full Scan (12 agents)</SelectItem>
                  <SelectItem value="quick">Quick Scan (top 5)</SelectItem>
                  <SelectItem value="stealth">Stealth Mode</SelectItem>
                  <SelectItem value="phase5">Phase 5 Only</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-end gap-2">
              {!scanRunning ? (
                <Button onClick={startScan} disabled={!targetUrl} className="gap-2">
                  <Play className="h-4 w-4" />
                  Launch
                </Button>
              ) : (
                <>
                  <Button variant="outline" onClick={() => {}} className="gap-2">
                    <Pause className="h-4 w-4" />
                    Pause
                  </Button>
                  <Button variant="destructive" onClick={stopScan} className="gap-2">
                    <Square className="h-4 w-4" />
                    Abort
                  </Button>
                </>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Stats bar */}
      {scanRunning && (
        <div className="grid grid-cols-4 gap-4">
          <MiniStat label="Agents Running" value={String(running)} icon={<Loader2 className="h-4 w-4 animate-spin text-blue-400" />} />
          <MiniStat label="Completed" value={`${completed}/12`} icon={<CheckCircle className="h-4 w-4 text-green-400" />} />
          <MiniStat label="Findings" value={String(totalFindings)} icon={<AlertTriangle className="h-4 w-4 text-yellow-400" />} />
          <MiniStat label="Elapsed" value="—" icon={<Clock className="h-4 w-4 text-muted-foreground" />} />
        </div>
      )}

      {/* Agent grid */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {agents.map((agent) => (
          <Card key={agent.code} className="overflow-hidden">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <StatusDot status={agent.status} />
                  <span className="text-sm font-bold text-primary">{agent.code}</span>
                </div>
                {agent.findings > 0 && (
                  <Badge variant="destructive" className="text-xs">
                    {agent.findings} findings
                  </Badge>
                )}
              </div>
              <p className="mt-1 text-xs text-muted-foreground">{agent.name}</p>
              {agent.status === "running" && (
                <div className="mt-3 space-y-1">
                  <Progress value={agent.progress} className="h-1.5" />
                  <p className="text-xs text-muted-foreground">{agent.currentTechnique}</p>
                </div>
              )}
              {agent.status === "completed" && (
                <div className="mt-3 flex items-center gap-1 text-xs text-green-400">
                  <CheckCircle className="h-3 w-3" />
                  Complete — {agent.techniques} techniques tested
                </div>
              )}
              {agent.status === "idle" && (
                <div className="mt-3 text-xs text-muted-foreground">
                  {agent.techniques} techniques ready
                </div>
              )}
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

function StatusDot({ status }: { status: string }) {
  const colors: Record<string, string> = {
    idle: "bg-gray-500",
    running: "bg-blue-500 animate-pulse",
    completed: "bg-green-500",
    error: "bg-red-500",
  };
  return <div className={`h-2 w-2 rounded-full ${colors[status] || "bg-gray-500"}`} />;
}

function MiniStat({ label, value, icon }: { label: string; value: string; icon: React.ReactNode }) {
  return (
    <Card>
      <CardContent className="flex items-center gap-3 p-3">
        {icon}
        <div>
          <p className="text-lg font-bold">{value}</p>
          <p className="text-xs text-muted-foreground">{label}</p>
        </div>
      </CardContent>
    </Card>
  );
}
