import { useState, useRef, useEffect } from "react";
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
import { startScan as apiStartScan, cancelScan, getAgentStatus, getLiveScanStatus } from "@/api/client";

interface AgentStatus {
  code: string;
  name: string;
  status: "idle" | "running" | "completed" | "error";
  progress: number;
  findings: number;
  techniques: number;
  currentTechnique?: string;
}

export function LiveScanPage() {
  const [agents, setAgents] = useState<AgentStatus[]>([]);
  const [scanRunning, setScanRunning] = useState(false);
  const [targetUrl, setTargetUrl] = useState("");
  const [scanMode, setScanMode] = useState("full");
  const [scanError, setScanError] = useState<string | null>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Load agent list from API on mount
  useEffect(() => {
    async function loadAgents() {
      try {
        const data = await getAgentStatus();
        setAgents(
          data.agents.map((a) => ({
            code: a.code,
            name: a.name,
            status: "idle" as const,
            progress: 0,
            findings: a.findings ?? 0,
            techniques: a.techniques ?? 5,
          }))
        );
      } catch {
        // Fallback: populate from known agent list
        setAgents(
          ["PI-01", "TP-02", "MP-03", "IS-04", "CW-05", "CX-06", "PE-07", "RC-08", "SC-09", "ME-10", "PH-11", "MB-12"].map((code) => ({
            code,
            name: code,
            status: "idle" as const,
            progress: 0,
            findings: 0,
            techniques: 5,
          }))
        );
      }
    }
    loadAgents();
  }, []);

  // Cleanup interval on unmount
  useEffect(() => {
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, []);

  const handleStartScan = async () => {
    if (!targetUrl) return;
    setScanError(null);
    try {
      await apiStartScan({
        target_name: targetUrl,
        target_url: targetUrl,
      });
      setScanRunning(true);
      // Poll the in-memory live scan status (NOT the DB-backed /agents/status)
      let step = 0;
      intervalRef.current = setInterval(async () => {
        step++;
        try {
          const data = await getLiveScanStatus();
          // Map in-memory agent state to our AgentStatus interface
          const agentEntries = Object.values(data.agents || {});
          if (agentEntries.length > 0) {
            setAgents((prev) => {
              // Build a lookup from type to previous agent metadata
              const prevByType = new Map(prev.map((a) => [a.code, a]));
              // The in-memory state uses agent_type as keys; map back to codes
              const codeMap: Record<string, string> = {
                prompt_injection_hunter: "PI-01", tool_poisoning: "TP-02",
                memory_poisoning: "MP-03", identity_spoof: "IS-04",
                context_window: "CW-05", cross_agent_exfiltration: "CX-06",
                privilege_escalation: "PE-07", race_condition: "RC-08",
                supply_chain: "SC-09", model_extraction: "ME-10",
                persona_hijacking: "PH-11", memory_boundary_collapse: "MB-12",
              };
              return agentEntries.map((a) => {
                const code = codeMap[a.type] || a.type;
                const prevAgent = prevByType.get(code);
                let status: AgentStatus["status"] = "idle";
                if (a.status === "running") status = "running";
                else if (a.status === "completed") status = "completed";
                else if (a.status === "pending") status = "idle";
                return {
                  code,
                  name: prevAgent?.name || code,
                  status,
                  progress: a.status === "completed" ? 100 : a.status === "running" ? Math.min(step * 8, 95) : 0,
                  findings: a.findings_count ?? 0,
                  techniques: prevAgent?.techniques ?? 5,
                  currentTechnique: a.status === "running" ? a.current_action : undefined,
                };
              });
            });
          }
          // Stop polling when scan is done
          if (data.status === "completed" || data.status === "failed" || data.status === "cancelled") {
            if (intervalRef.current) clearInterval(intervalRef.current);
            intervalRef.current = null;
            setScanRunning(false);
          }
        } catch {
          // Polling failed, keep trying
        }
        if (step > 120) {
          if (intervalRef.current) clearInterval(intervalRef.current);
          intervalRef.current = null;
          setScanRunning(false);
        }
      }, 2000);
    } catch (err) {
      setScanError(err instanceof Error ? err.message : "Failed to start scan");
    }
  };

  const handleStopScan = async () => {
    try {
      await cancelScan();
    } catch {
      // ignore cancel errors
    }
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
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
                <Button onClick={handleStartScan} disabled={!targetUrl} className="gap-2">
                  <Play className="h-4 w-4" />
                  Launch
                </Button>
              ) : (
                <>
                  <Button variant="outline" onClick={() => {}} className="gap-2">
                    <Pause className="h-4 w-4" />
                    Pause
                  </Button>
                  <Button variant="destructive" onClick={handleStopScan} className="gap-2">
                    <Square className="h-4 w-4" />
                    Abort
                  </Button>
                </>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Scan error banner */}
      {scanError && (
        <div className="flex items-center justify-between rounded-md border border-red-500/50 bg-red-950/20 p-3 text-sm text-red-400">
          <span>{scanError}</span>
          <Button variant="ghost" size="sm" className="h-6 text-red-400 hover:text-red-300" onClick={() => setScanError(null)}>Dismiss</Button>
        </div>
      )}

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
