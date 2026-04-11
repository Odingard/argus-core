import { useState, useEffect } from "react";
import {
  Sword,
  Play,
  CheckCircle,
  XCircle,
  Clock,
  Download,
  Loader2,
  AlertTriangle,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { getGauntletScenarios } from "@/api/client";

interface BenchmarkScenario {
  id: string;
  name: string;
  agent: string;
  category: string;
  status: string;
  score: number;
  maxScore: number;
  description: string;
}

const STATUS_CONFIG: Record<string, { icon: React.ElementType; label: string; color: string }> = {
  passed: { icon: CheckCircle, label: "Passed", color: "text-green-400 border-green-400/50" },
  failed: { icon: XCircle, label: "Failed", color: "text-red-400 border-red-400/50" },
  pending: { icon: Clock, label: "Pending", color: "text-muted-foreground border-border" },
  running: { icon: Clock, label: "Running", color: "text-blue-400 border-blue-400/50" },
};

export function GauntletPage() {
  const [scenarios, setScenarios] = useState<BenchmarkScenario[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        setLoading(true);
        const data = await getGauntletScenarios();
        if (cancelled) return;
        setScenarios(
          (data.scenarios || []).map((s) => ({
            id: s.id,
            name: s.name,
            agent: s.agent,
            category: s.category,
            status: s.status,
            score: s.score,
            maxScore: s.maxScore,
            description: s.description,
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
          const config = STATUS_CONFIG[scenario.status] || STATUS_CONFIG.pending;
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
