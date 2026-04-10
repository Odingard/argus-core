import { useState } from "react";
import {
  Sword,
  Play,
  CheckCircle,
  XCircle,
  Clock,
  Download,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";

interface BenchmarkScenario {
  id: string;
  name: string;
  agent: string;
  category: string;
  status: "passed" | "failed" | "pending" | "running";
  score: number;
  maxScore: number;
  description: string;
}

const MOCK_SCENARIOS: BenchmarkScenario[] = [
  { id: "BM-01", name: "Basic Prompt Injection", agent: "PI-01", category: "prompt_injection", status: "passed", score: 95, maxScore: 100, description: "Tests detection of standard injection patterns" },
  { id: "BM-02", name: "Unicode Hidden Instructions", agent: "TP-02", category: "tool_poisoning", status: "passed", score: 88, maxScore: 100, description: "Tests detection of zero-width character hiding" },
  { id: "BM-03", name: "Memory Store Poisoning", agent: "MP-03", category: "memory_poisoning", status: "passed", score: 82, maxScore: 100, description: "Tests adversarial content planting and retrieval" },
  { id: "BM-04", name: "Identity Header Forgery", agent: "IS-04", category: "identity_spoof", status: "passed", score: 91, maxScore: 100, description: "Tests A2A authentication bypass via header spoofing" },
  { id: "BM-05", name: "Context Window Overflow", agent: "CW-05", category: "context_window", status: "failed", score: 45, maxScore: 100, description: "Tests long-con multi-turn context manipulation" },
  { id: "BM-06", name: "Cross-Agent Data Relay", agent: "CX-06", category: "cross_agent_exfil", status: "passed", score: 77, maxScore: 100, description: "Tests data leakage between agent boundaries" },
  { id: "BM-07", name: "Confused Deputy Escalation", agent: "PE-07", category: "privilege_escalation", status: "passed", score: 84, maxScore: 100, description: "Tests chained tool-call privilege escalation" },
  { id: "BM-08", name: "TOCTOU Race Condition", agent: "RC-08", category: "race_condition", status: "pending", score: 0, maxScore: 100, description: "Tests time-of-check/time-of-use exploitation" },
  { id: "BM-09", name: "Supply Chain Dependency", agent: "SC-09", category: "supply_chain", status: "pending", score: 0, maxScore: 100, description: "Tests external dependency trust verification" },
  { id: "BM-10", name: "System Prompt Extraction", agent: "ME-10", category: "model_extraction", status: "passed", score: 86, maxScore: 100, description: "Tests system prompt and config fingerprinting" },
  { id: "BM-11", name: "Persona Drift Induction", agent: "PH-11", category: "persona_hijacking", status: "passed", score: 92, maxScore: 100, description: "Tests identity drift via multi-turn adversarial pressure" },
  { id: "BM-12", name: "Memory Boundary Bleed", agent: "MB-12", category: "memory_boundary", status: "passed", score: 89, maxScore: 100, description: "Tests cross-session memory boundary enforcement" },
];

const STATUS_CONFIG = {
  passed: { icon: CheckCircle, label: "Passed", color: "text-green-400 border-green-400/50" },
  failed: { icon: XCircle, label: "Failed", color: "text-red-400 border-red-400/50" },
  pending: { icon: Clock, label: "Pending", color: "text-muted-foreground border-border" },
  running: { icon: Clock, label: "Running", color: "text-blue-400 border-blue-400/50" },
};

export function GauntletPage() {
  const [scenarios] = useState(MOCK_SCENARIOS);

  const passed = scenarios.filter((s) => s.status === "passed").length;
  const failed = scenarios.filter((s) => s.status === "failed").length;
  const pending = scenarios.filter((s) => s.status === "pending").length;
  const totalScore = scenarios.filter((s) => s.status !== "pending").reduce((s, sc) => s + sc.score, 0);
  const maxScore = scenarios.filter((s) => s.status !== "pending").reduce((s, sc) => s + sc.maxScore, 0);
  const overallPct = maxScore > 0 ? Math.round((totalScore / maxScore) * 100) : 0;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">ARGUS Gauntlet</h2>
          <p className="text-sm text-muted-foreground">
            Benchmark suite — prove ARGUS works before deploying against a client
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" className="gap-1">
            <Download className="h-3 w-3" />
            Export Report
          </Button>
          <Button className="gap-2">
            <Play className="h-4 w-4" />
            Run Gauntlet
          </Button>
        </div>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4">
            <p className="text-sm text-muted-foreground">Overall Score</p>
            <p className="mt-1 text-2xl font-bold">{overallPct}%</p>
            <Progress value={overallPct} className="mt-2 h-1.5" />
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <p className="text-sm text-muted-foreground">Passed</p>
            <p className="mt-1 text-2xl font-bold text-green-400">{passed}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <p className="text-sm text-muted-foreground">Failed</p>
            <p className="mt-1 text-2xl font-bold text-red-400">{failed}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <p className="text-sm text-muted-foreground">Pending</p>
            <p className="mt-1 text-2xl font-bold text-muted-foreground">{pending}</p>
          </CardContent>
        </Card>
      </div>

      {/* Scenarios */}
      <div className="space-y-3">
        {scenarios.map((scenario) => {
          const config = STATUS_CONFIG[scenario.status];
          const StatusIcon = config.icon;

          return (
            <Card key={scenario.id}>
              <CardContent className="flex items-center gap-4 p-4">
                <Badge variant="outline" className={`gap-1 ${config.color}`}>
                  <StatusIcon className="h-3 w-3" />
                  {config.label}
                </Badge>

                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-bold text-primary">{scenario.id}</span>
                    <span className="text-sm font-medium">{scenario.name}</span>
                    <Badge variant="secondary" className="text-xs font-mono">{scenario.agent}</Badge>
                  </div>
                  <p className="mt-1 text-xs text-muted-foreground">{scenario.description}</p>
                </div>

                {scenario.status !== "pending" && (
                  <div className="flex items-center gap-2 text-right">
                    <div>
                      <p className="text-lg font-bold">
                        {scenario.score}<span className="text-sm text-muted-foreground">/{scenario.maxScore}</span>
                      </p>
                    </div>
                    <div className="w-24">
                      <Progress
                        value={(scenario.score / scenario.maxScore) * 100}
                        className={`h-1.5 ${
                          scenario.score / scenario.maxScore > 0.8 ? "[&>div]:bg-green-500" :
                          scenario.score / scenario.maxScore > 0.5 ? "[&>div]:bg-yellow-500" :
                          "[&>div]:bg-red-500"
                        }`}
                      />
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Demo mode */}
      <Card className="border-primary/30">
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-sm font-medium text-primary">
            <Sword className="h-4 w-4" />
            Demo Mode
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            Run the Gauntlet against the built-in mock target to demonstrate ARGUS capabilities
            without connecting to a live system. Perfect for client demos and validation.
          </p>
          <Button variant="outline" size="sm" className="mt-3 gap-1">
            <Play className="h-3 w-3" />
            Launch Demo
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
