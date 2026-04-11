import { useState, useEffect } from "react";
import {
  Bot,
  Plus,
  Shield,
  Fingerprint,
  AlertTriangle,
  CheckCircle,
  Loader2,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
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

interface AIAgent {
  id: string;
  name: string;
  endpoint: string;
  model: string;
  status: string;
  personaBaseline: boolean;
  driftScore: number;
  lastScan: string;
  capabilities: string[];
  findings: { critical: number; high: number; medium: number; low: number };
}

export function AIAgentsPage() {
  const [agents, setAgents] = useState<AIAgent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [newName, setNewName] = useState("");
  const [newEndpoint, setNewEndpoint] = useState("");
  const [newModel, setNewModel] = useState("");

  useEffect(() => { loadAgents(); }, []);

  async function loadAgents() {
    try {
      setLoading(true);
      const data = await getTargets();
      const aiTargets = (data.targets || []).filter(
        (t: Record<string, unknown>) => String(t.target_type ?? t.type ?? "").toLowerCase().includes("ai_agent")
      );
      setAgents(
        aiTargets.map((t: Record<string, unknown>) => ({
          id: String(t.id ?? ""),
          name: String(t.name ?? ""),
          endpoint: String(t.url ?? t.endpoint ?? ""),
          model: String(t.model ?? "Unknown"),
          status: String(t.status ?? "healthy"),
          personaBaseline: Boolean(t.persona_baseline ?? false),
          driftScore: Number(t.drift_score ?? 0),
          lastScan: String(t.last_scan ?? "Never"),
          capabilities: Array.isArray(t.capabilities) ? (t.capabilities as string[]) : [],
          findings: { critical: 0, high: 0, medium: 0, low: 0 },
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
    if (!newName || !newEndpoint) return;
    try {
      await createTarget({ name: newName, agent_endpoint: newEndpoint, target_type: "ai_agent", description: newModel ? `Model: ${newModel}` : "" });
      setNewName(""); setNewEndpoint(""); setNewModel("");
      loadAgents();
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
        <Button variant="outline" size="sm" className="mt-4" onClick={() => loadAgents()}>Retry</Button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">AI Agents</h2>
          <p className="text-sm text-muted-foreground">
            Agent targets — capability profile, persona baseline, drift detection
          </p>
        </div>
        <Dialog>
          <DialogTrigger asChild>
            <Button className="gap-2">
              <Plus className="h-4 w-4" />
              Add Agent
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Add AI Agent Target</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 pt-4">
              <div>
                <Label>Agent Name</Label>
                <Input placeholder="Customer Support Agent" className="mt-1" value={newName} onChange={(e) => setNewName(e.target.value)} />
              </div>
              <div>
                <Label>Agent Endpoint</Label>
                <Input placeholder="https://api.example.com/agents/support" className="mt-1" value={newEndpoint} onChange={(e) => setNewEndpoint(e.target.value)} />
              </div>
              <div>
                <Label>Model</Label>
                <Input placeholder="GPT-4o, Claude 3.5, etc." className="mt-1" value={newModel} onChange={(e) => setNewModel(e.target.value)} />
              </div>
              <Button className="w-full" onClick={handleAdd}>Add Agent</Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      {agents.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Bot className="h-12 w-12 text-muted-foreground/30" />
            <p className="mt-4 text-sm text-muted-foreground">No AI agent targets configured</p>
          </CardContent>
        </Card>
      ) : (
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {agents.map((agent) => (
          <Card key={agent.id}>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-md bg-primary/10">
                    <Bot className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <CardTitle className="text-base">{agent.name}</CardTitle>
                    <p className="text-xs text-muted-foreground">{agent.model} • {agent.endpoint}</p>
                  </div>
                </div>
                {agent.status === "drift_detected" ? (
                  <Badge className="gap-1 bg-red-600">
                    <AlertTriangle className="h-3 w-3" />
                    Drift Detected
                  </Badge>
                ) : (
                  <Badge variant="outline" className="gap-1 text-green-400 border-green-400/50">
                    <CheckCircle className="h-3 w-3" />
                    Healthy
                  </Badge>
                )}
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {agent.capabilities.length > 0 && (
              <div className="flex flex-wrap gap-1">
                {agent.capabilities.map((cap) => (
                  <Badge key={cap} variant="secondary" className="text-xs">
                    {cap}
                  </Badge>
                ))}
              </div>
              )}

              <div className="grid grid-cols-2 gap-4">
                <div className="rounded-md border border-border p-3">
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <Fingerprint className="h-3 w-3" />
                    Persona Baseline
                  </div>
                  <p className="mt-1 text-sm font-medium">
                    {agent.personaBaseline ? "Established" : "Not Set"}
                  </p>
                </div>
                <div className="rounded-md border border-border p-3">
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <Shield className="h-3 w-3" />
                    Drift Score
                  </div>
                  <p className={`mt-1 text-lg font-bold ${agent.driftScore > 50 ? "text-red-500" : agent.driftScore > 25 ? "text-yellow-500" : "text-green-500"}`}>
                    {agent.driftScore}%
                  </p>
                </div>
              </div>

              {agent.personaBaseline && (
                <Progress
                  value={agent.driftScore}
                  className={`h-1.5 ${agent.driftScore > 50 ? "[&>div]:bg-red-500" : agent.driftScore > 25 ? "[&>div]:bg-yellow-500" : "[&>div]:bg-green-500"}`}
                />
              )}

              <div className="flex items-center gap-2">
                <span className="text-xs text-muted-foreground">Findings:</span>
                {agent.findings.critical > 0 && <Badge className="bg-red-600 text-xs">{agent.findings.critical}C</Badge>}
                {agent.findings.high > 0 && <Badge className="bg-orange-600 text-xs">{agent.findings.high}H</Badge>}
                {agent.findings.medium > 0 && <Badge className="bg-yellow-600 text-xs">{agent.findings.medium}M</Badge>}
                {agent.findings.low > 0 && <Badge variant="secondary" className="text-xs">{agent.findings.low}L</Badge>}
                {Object.values(agent.findings).every((v) => v === 0) && (
                  <span className="text-xs text-muted-foreground">None — scan required</span>
                )}
              </div>

              <p className="text-xs text-muted-foreground">Last scan: {agent.lastScan}</p>
            </CardContent>
          </Card>
        ))}
      </div>
      )}
    </div>
  );
}
