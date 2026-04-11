import { useState, useEffect } from "react";
import {
  GitBranch,
  Plus,
  ArrowRight,
  Shield,
  AlertTriangle,
  Loader2,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { getTargets, createTarget } from "@/api/client";

interface Pipeline {
  id: string;
  name: string;
  agents: { name: string; trust: "high" | "medium" | "low" }[];
  trustBoundaries: number;
  lastScan: string;
  findings: number;
  criticalPaths: number;
}

const TRUST_COLORS = {
  high: "text-green-400 border-green-400/50",
  medium: "text-yellow-400 border-yellow-400/50",
  low: "text-red-400 border-red-400/50",
};

export function PipelinesPage() {
  const [pipelines, setPipelines] = useState<Pipeline[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");

  useEffect(() => { loadPipelines(); }, []);

  async function loadPipelines() {
    try {
      setLoading(true);
      const data = await getTargets();
      const pipeTargets = (data.targets || []).filter(
        (t: Record<string, unknown>) => String(t.target_type ?? t.type ?? "").toLowerCase().includes("pipeline")
      );
      setPipelines(
        pipeTargets.map((t: Record<string, unknown>) => ({
          id: String(t.id ?? ""),
          name: String(t.name ?? ""),
          agents: Array.isArray(t.agents) ? (t.agents as { name: string; trust: "high" | "medium" | "low" }[]) : [],
          trustBoundaries: Number(t.trust_boundaries ?? 0),
          lastScan: String(t.last_scan ?? "Never"),
          findings: Number(t.findings ?? 0),
          criticalPaths: Number(t.critical_paths ?? 0),
        }))
      );
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load");
    } finally {
      setLoading(false);
    }
  }

  async function handleAdd() {
    if (!newName) return;
    try {
      await createTarget({ name: newName, type: "pipeline", description: newDesc });
      setNewName(""); setNewDesc("");
      loadPipelines();
    } catch { /* ignore */ }
  }

  if (loading) {
    return (<div className="flex items-center justify-center py-20"><Loader2 className="h-8 w-8 animate-spin text-primary" /></div>);
  }
  if (error) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-center">
        <AlertTriangle className="h-8 w-8 text-red-500" />
        <p className="mt-2 text-sm text-muted-foreground">{error}</p>
        <Button variant="outline" size="sm" className="mt-4" onClick={() => loadPipelines()}>Retry</Button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Multi-Agent Pipelines</h2>
          <p className="text-sm text-muted-foreground">
            Map agent-to-agent communication paths and trust boundaries
          </p>
        </div>
        <Dialog>
          <DialogTrigger asChild>
            <Button className="gap-2">
              <Plus className="h-4 w-4" />
              Add Pipeline
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Add Multi-Agent Pipeline</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 pt-4">
              <div>
                <Label>Pipeline Name</Label>
                <Input placeholder="Customer Intake Pipeline" className="mt-1" value={newName} onChange={(e) => setNewName(e.target.value)} />
              </div>
              <div>
                <Label>Description</Label>
                <Input placeholder="Describe the pipeline flow" className="mt-1" value={newDesc} onChange={(e) => setNewDesc(e.target.value)} />
              </div>
              <Button className="w-full" onClick={handleAdd}>Add Pipeline</Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      {pipelines.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <GitBranch className="h-12 w-12 text-muted-foreground/30" />
            <p className="mt-4 text-sm text-muted-foreground">No pipelines configured</p>
          </CardContent>
        </Card>
      ) : (
      <div className="space-y-4">
        {pipelines.map((pipeline) => (
          <Card key={pipeline.id}>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-md bg-primary/10">
                    <GitBranch className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <CardTitle className="text-base">{pipeline.name}</CardTitle>
                    <p className="text-xs text-muted-foreground">
                      {pipeline.agents.length} agents • {pipeline.trustBoundaries} trust boundaries
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {pipeline.criticalPaths > 0 && (
                    <Badge className="gap-1 bg-red-600">
                      <AlertTriangle className="h-3 w-3" />
                      {pipeline.criticalPaths} critical path{pipeline.criticalPaths > 1 ? "s" : ""}
                    </Badge>
                  )}
                  <Badge variant="secondary">{pipeline.findings} findings</Badge>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {pipeline.agents.length > 0 && (
              <div className="flex items-center gap-2 overflow-x-auto py-2">
                {pipeline.agents.map((agent, i) => (
                  <div key={agent.name} className="flex items-center gap-2">
                    <div className="rounded-md border border-border bg-background p-3 text-center min-w-28">
                      <p className="text-sm font-medium">{agent.name}</p>
                      <Badge variant="outline" className={`mt-1 text-xs ${TRUST_COLORS[agent.trust] ?? ""}`}>
                        <Shield className="mr-1 h-2.5 w-2.5" />
                        {agent.trust}
                      </Badge>
                    </div>
                    {i < pipeline.agents.length - 1 && (
                      <ArrowRight className="h-4 w-4 shrink-0 text-muted-foreground" />
                    )}
                  </div>
                ))}
              </div>
              )}
              <p className="mt-3 text-xs text-muted-foreground">Last scan: {pipeline.lastScan}</p>
            </CardContent>
          </Card>
        ))}
      </div>
      )}
    </div>
  );
}
