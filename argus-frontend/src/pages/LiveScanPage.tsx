import { useState, useRef, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import {
  Radio,
  Play,
  Square,
  Pause,
  AlertTriangle,
  CheckCircle,
  Clock,
  Loader2,
  Eye,
  Terminal,
  Shield,
  Zap,
  Search,
  Bug,
  ChevronDown,
  ChevronRight,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { startScan as apiStartScan, cancelScan, getAgentStatus, getLiveScanStatus } from "@/api/client";
import type { ActivityEntry } from "@/api/client";

interface AgentStatus {
  code: string;
  name: string;
  type: string;
  status: "idle" | "running" | "completed" | "error";
  progress: number;
  findings: number;
  techniques: number;
  currentTechnique?: string;
}

const CATEGORY_STYLES: Record<string, { color: string; icon: typeof Terminal; label: string }> = {
  status: { color: "text-blue-400", icon: Shield, label: "STATUS" },
  probe: { color: "text-cyan-400", icon: Search, label: "PROBE" },
  finding: { color: "text-red-400", icon: Bug, label: "FINDING" },
  technique: { color: "text-yellow-400", icon: Zap, label: "TECHNIQUE" },
  recon: { color: "text-purple-400", icon: Eye, label: "RECON" },
};

const AGENT_LABELS: Record<string, string> = {
  prompt_injection_hunter: "Prompt Injection",
  tool_poisoning: "Tool Poisoning",
  memory_poisoning: "Memory Poisoning",
  identity_spoof: "Identity Spoof",
  context_window: "Context Window",
  cross_agent_exfiltration: "Cross-Agent Exfil",
  privilege_escalation: "Privilege Escalation",
  race_condition: "Race Condition",
  supply_chain: "Supply Chain",
  model_extraction: "Model Extraction",
  persona_hijacking: "Persona Hijacking",
  memory_boundary_collapse: "Memory Boundary",
};

const AGENT_CODE_MAP: Record<string, string> = {
  prompt_injection_hunter: "PI-01",
  tool_poisoning: "TP-02",
  memory_poisoning: "MP-03",
  identity_spoof: "IS-04",
  context_window: "CW-05",
  cross_agent_exfiltration: "CX-06",
  privilege_escalation: "PE-07",
  race_condition: "RC-08",
  supply_chain: "SC-09",
  model_extraction: "ME-10",
  persona_hijacking: "PH-11",
  memory_boundary_collapse: "MB-12",
};

export function LiveScanPage() {
  const navigate = useNavigate();
  const [agents, setAgents] = useState<AgentStatus[]>([]);
  const [scanRunning, setScanRunning] = useState(false);
  const [scanComplete, setScanComplete] = useState(false);
  const [scanId, setScanId] = useState<string | null>(null);
  const [targetUrl, setTargetUrl] = useState("");
  const [scanMode, setScanMode] = useState("full");
  const [targetToken, setTargetToken] = useState("");
  const [scanError, setScanError] = useState<string | null>(null);
  const [activityLog, setActivityLog] = useState<ActivityEntry[]>([]);
  const [expandedAgents, setExpandedAgents] = useState<Set<string>>(new Set());
  const [activeView, setActiveView] = useState<"agents" | "feed">("feed");
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const feedEndRef = useRef<HTMLDivElement>(null);
  const feedContainerRef = useRef<HTMLDivElement>(null);
  const activitySeenRef = useRef<number>(0);
  const userScrolledUpRef = useRef(false);
  const [showJumpToLatest, setShowJumpToLatest] = useState(false);

  // Auto-scroll feed to bottom ONLY when user hasn't scrolled up
  useEffect(() => {
    if (!userScrolledUpRef.current && feedEndRef.current) {
      feedEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [activityLog.length]);

  // Detect when user scrolls up in the feed
  const handleFeedScroll = useCallback((e: React.UIEvent<HTMLDivElement>) => {
    const el = e.currentTarget;
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
    userScrolledUpRef.current = !atBottom;
    setShowJumpToLatest(!atBottom);
  }, []);

  useEffect(() => {
    async function loadAgents() {
      try {
        const data = await getAgentStatus();
        setAgents(
          data.agents.map((a) => ({
            code: a.code,
            name: a.name,
            type: a.type,
            status: "idle" as const,
            progress: 0,
            findings: a.findings ?? 0,
            techniques: a.techniques ?? 5,
          }))
        );
      } catch {
        setAgents(
          Object.entries(AGENT_CODE_MAP).map(([type, code]) => ({
            code,
            name: AGENT_LABELS[type] || type,
            type,
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

  useEffect(() => {
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, []);

  const toggleAgent = useCallback((agentType: string) => {
    setExpandedAgents((prev) => {
      const next = new Set(prev);
      if (next.has(agentType)) next.delete(agentType);
      else next.add(agentType);
      return next;
    });
  }, []);

  const handleStartScan = async () => {
    if (!targetUrl) return;
    setScanError(null);
    setScanComplete(false);
    setScanId(null);
    setActivityLog([]);
    activitySeenRef.current = 0;
    userScrolledUpRef.current = false;
    setShowJumpToLatest(false);
    setElapsedSeconds(0);
    try {
      const scanBody: Record<string, unknown> = {
        target_name: targetUrl,
        mcp_urls: [targetUrl],
        agent_endpoint: targetUrl,
        demo_pace_seconds: 1.5,
      };
      if (targetToken.trim()) {
        scanBody.agent_api_key = targetToken.trim();
      }
      const result = await apiStartScan(scanBody);
      const newScanId = result.scan_id ? String(result.scan_id) : null;
      setScanId(newScanId);
      setScanRunning(true);
      setActiveView("feed");
      let step = 0;
      intervalRef.current = setInterval(async () => {
        step++;
        try {
          const data = await getLiveScanStatus();
          setElapsedSeconds(Math.round(data.elapsed_seconds || 0));

          const serverLog: ActivityEntry[] = data.activity_log || [];
          if (serverLog.length > 0) {
            const lastSeenSeq = activitySeenRef.current;
            const newEntries = serverLog.filter((e) => (e.seq ?? 0) > lastSeenSeq);
            if (newEntries.length > 0) {
              activitySeenRef.current = Math.max(...newEntries.map((e) => e.seq ?? 0));
              setActivityLog((prev) => [...prev, ...newEntries]);
            }
          }

          const agentEntries = Object.values(data.agents || {});
          if (agentEntries.length > 0) {
            setAgents((prev) => {
              const prevByCode = new Map(prev.map((a) => [a.code, a]));
              return agentEntries.map((a) => {
                const code = AGENT_CODE_MAP[a.type] || a.type;
                const prevAgent = prevByCode.get(code);
                let status: AgentStatus["status"] = "idle";
                if (a.status === "running") status = "running";
                else if (a.status === "completed") status = "completed";
                else if (a.status === "pending") status = "idle";
                return {
                  code,
                  name: AGENT_LABELS[a.type] || prevAgent?.name || code,
                  type: a.type,
                  status,
                  progress: a.status === "completed" ? 100 : a.status === "running" ? Math.min(step * 8, 95) : 0,
                  findings: a.findings_count ?? 0,
                  techniques: a.techniques_attempted ?? prevAgent?.techniques ?? 5,
                  currentTechnique: a.status === "running" ? a.current_action : undefined,
                };
              });
            });

            for (const a of agentEntries) {
              if (a.status === "running") {
                setExpandedAgents((prev) => {
                  if (prev.has(a.type)) return prev;
                  const next = new Set(prev);
                  next.add(a.type);
                  return next;
                });
              }
            }
          }

          if (data.status === "completed" || data.status === "failed" || data.status === "cancelled") {
            if (intervalRef.current) clearInterval(intervalRef.current);
            intervalRef.current = null;
            setScanRunning(false);
            if (data.status === "completed") setScanComplete(true);
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
  const total = agents.length || 12;

  const activityByAgent: Record<string, ActivityEntry[]> = {};
  for (const entry of activityLog) {
    if (!activityByAgent[entry.agent]) activityByAgent[entry.agent] = [];
    activityByAgent[entry.agent].push(entry);
  }

  const formatTime = (seconds: number) => {
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return `${m}:${String(s).padStart(2, "0")}`;
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Live Scan</h2>
          <p className="text-sm text-muted-foreground">
            Deploy all 12 agents against a target simultaneously
          </p>
        </div>
        <div className="flex items-center gap-2">
          {scanRunning && (
            <Badge variant="outline" className="gap-2 text-green-400 border-green-400/50">
              <Radio className="h-3 w-3 animate-pulse" />
              Scan Active
            </Badge>
          )}
          {scanComplete && scanId && (
            <Button size="sm" className="gap-1" onClick={() => navigate(`/scan/${scanId}`)}>
              <Eye className="h-3 w-3" />
              View Results
            </Button>
          )}
        </div>
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
            <div className="flex-1">
              <Label className="text-xs">Target Auth Token {targetToken ? "(set)" : "(optional)"}</Label>
              <Input
                placeholder="JWT or Bearer token for authenticated scanning"
                value={targetToken}
                onChange={(e) => setTargetToken(e.target.value)}
                disabled={scanRunning}
                className="mt-1 font-mono text-xs"
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

      {(scanRunning || scanComplete) && (
        <div className="grid grid-cols-4 gap-4">
          <MiniStat label="Agents Running" value={String(running)} icon={<Loader2 className="h-4 w-4 animate-spin text-blue-400" />} />
          <MiniStat label="Completed" value={`${completed}/${total}`} icon={<CheckCircle className="h-4 w-4 text-green-400" />} />
          <MiniStat label="Findings" value={String(totalFindings)} icon={<AlertTriangle className="h-4 w-4 text-yellow-400" />} />
          <MiniStat label="Elapsed" value={formatTime(elapsedSeconds)} icon={<Clock className="h-4 w-4 text-muted-foreground" />} />
        </div>
      )}

      {/* War Room: side-by-side agents + feed */}
      {(scanRunning || scanComplete || activityLog.length > 0) && (
        <div className="grid grid-cols-12 gap-3" style={{ height: "calc(100vh - 320px)", minHeight: "400px" }}>
          {/* Left: Agent Grid (compact) */}
          <div className="col-span-4 overflow-y-auto space-y-1.5 pr-1">
            <div className="flex items-center gap-1.5 mb-1">
              <Shield className="h-3.5 w-3.5 text-primary" />
              <span className="text-xs font-semibold text-primary uppercase tracking-wider">Agents</span>
            </div>
            {agents.map((agent) => {
              const agentEvents = activityByAgent[agent.type] || [];
              const findingCount = agentEvents.filter((e) => e.category === "finding").length;
              const isExpanded = expandedAgents.has(agent.type);
              return (
                <div key={agent.code}>
                  <button
                    onClick={() => toggleAgent(agent.type)}
                    className={`w-full flex items-center gap-2 rounded px-2 py-1.5 text-left transition-colors ${
                      agent.status === "running" ? "bg-blue-950/40 border border-blue-500/30" :
                      agent.status === "completed" ? "bg-green-950/20 border border-green-500/20" :
                      "bg-muted/20 border border-transparent"
                    } hover:bg-muted/30`}
                  >
                    <StatusDot status={agent.status} />
                    <span className="font-mono text-[11px] font-bold text-primary w-10">{agent.code}</span>
                    <span className="text-[11px] text-muted-foreground truncate flex-1">{agent.name}</span>
                    {agent.status === "running" && <Loader2 className="h-3 w-3 animate-spin text-blue-400 shrink-0" />}
                    {findingCount > 0 && <span className="text-[10px] font-bold text-red-400 shrink-0">{findingCount}F</span>}
                    {agent.status === "completed" && <CheckCircle className="h-3 w-3 text-green-400 shrink-0" />}
                  </button>
                  {isExpanded && agentEvents.length > 0 && (
                    <div className="ml-2 mt-0.5 mb-1 rounded border border-border/30 bg-black/30 p-1.5 max-h-28 overflow-y-auto">
                      {agentEvents.slice(-10).map((entry, i) => (
                        <ActivityLine key={i} entry={entry} compact />
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Right: Activity Feed */}
          <div className="col-span-8 flex flex-col rounded-lg border border-primary/20 overflow-hidden">
            <div className="flex items-center justify-between px-3 py-1.5 bg-black/40 border-b border-border/30">
              <div className="flex items-center gap-1.5">
                <Terminal className="h-3.5 w-3.5 text-green-400" />
                <span className="text-[11px] font-mono text-green-400 font-semibold">LIVE FEED</span>
              </div>
              <div className="flex items-center gap-2">
                {showJumpToLatest && (
                  <button
                    className="text-[10px] font-mono text-yellow-400 hover:text-yellow-300"
                    onClick={() => {
                      userScrolledUpRef.current = false;
                      setShowJumpToLatest(false);
                      feedEndRef.current?.scrollIntoView({ behavior: "smooth" });
                    }}
                  >
                    ↓ Jump to latest
                  </button>
                )}
                <span className="font-mono text-[10px] text-muted-foreground">{activityLog.length} events</span>
              </div>
            </div>
            <div
              ref={feedContainerRef}
              className="flex-1 overflow-y-auto bg-black/40 p-2"
              onScroll={handleFeedScroll}
            >
              <div className="font-mono space-y-px">
                {activityLog.length === 0 && scanRunning && (
                  <div className="text-muted-foreground animate-pulse py-8 text-center text-[11px]">
                    Waiting for agent activity...
                  </div>
                )}
                {activityLog.map((entry, i) => (
                  <ActivityLine key={i} entry={entry} />
                ))}
                <div ref={feedEndRef} />
              </div>
            </div>
          </div>
        </div>
      )}

      {(!scanRunning && !scanComplete && activityLog.length === 0) && (
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
        {agents.map((agent) => (
          <Card key={agent.code} className="overflow-hidden">
            <CardContent className="p-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <StatusDot status={agent.status} />
                  <span className="text-xs font-bold text-primary">{agent.code}</span>
                </div>
                {agent.findings > 0 && (
                  <Badge variant="destructive" className="text-[10px] px-1.5 py-0">
                    {agent.findings}
                  </Badge>
                )}
              </div>
              <p className="mt-0.5 text-[11px] text-muted-foreground">{agent.name}</p>
              {agent.status === "running" && (
                <div className="mt-2 space-y-1">
                  <Progress value={agent.progress} className="h-1" />
                  <p className="text-[10px] text-muted-foreground truncate">{agent.currentTechnique}</p>
                </div>
              )}
              {agent.status === "completed" && (
                <div className="mt-2 flex items-center gap-1 text-[10px] text-green-400">
                  <CheckCircle className="h-2.5 w-2.5" />
                  {agent.techniques} techniques
                </div>
              )}
              {agent.status === "idle" && (
                <div className="mt-2 text-[10px] text-muted-foreground">
                  {agent.techniques} techniques ready
                </div>
              )}
            </CardContent>
          </Card>
        ))}
      </div>
      )}
    </div>
  );
}

function ActivityLine({ entry, compact }: { entry: ActivityEntry; compact?: boolean }) {
  const style = CATEGORY_STYLES[entry.category] || CATEGORY_STYLES.status;
  const Icon = style.icon;
  const agentLabel = compact ? "" : `[${AGENT_LABELS[entry.agent] || entry.agent}]`;
  const time = new Date(entry.ts * 1000);
  const timeStr = time.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
  const fontSize = compact ? "text-[10px]" : "text-[11px]";

  return (
    <div className={`flex items-start gap-1 leading-tight py-px hover:bg-white/5 rounded px-1 group ${fontSize}`}>
      <span className="text-muted-foreground/60 shrink-0 w-[52px]">{timeStr}</span>
      <Icon className={`h-2.5 w-2.5 mt-[2px] shrink-0 ${style.color}`} />
      <span className={`shrink-0 font-semibold ${style.color} w-[56px] uppercase`}>{style.label}</span>
      {!compact && (
        <span className="text-primary/70 shrink-0 max-w-[120px] truncate">{agentLabel}</span>
      )}
      <span className="text-foreground/90 truncate">{entry.action}</span>
      {entry.detail && (
        <span className="text-muted-foreground/60 truncate hidden group-hover:inline">
          — {entry.detail}
        </span>
      )}
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
