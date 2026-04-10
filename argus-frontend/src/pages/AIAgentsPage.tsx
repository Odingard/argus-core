import {
  Bot,
  Plus,
  Shield,
  Fingerprint,
  AlertTriangle,
  CheckCircle,
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

const MOCK_AGENTS = [
  {
    id: "agent-001",
    name: "Customer Support Agent",
    endpoint: "https://api.example.com/agents/support",
    model: "GPT-4o",
    status: "healthy",
    personaBaseline: true,
    driftScore: 12,
    lastScan: "3 hours ago",
    capabilities: ["RAG", "Tool Use", "Multi-turn"],
    findings: { critical: 0, high: 1, medium: 2, low: 1 },
  },
  {
    id: "agent-002",
    name: "Code Review Agent",
    endpoint: "https://api.example.com/agents/code-review",
    model: "Claude 3.5",
    status: "drift_detected",
    personaBaseline: true,
    driftScore: 67,
    lastScan: "1 hour ago",
    capabilities: ["Code Analysis", "Tool Use", "File Access"],
    findings: { critical: 1, high: 2, medium: 3, low: 0 },
  },
  {
    id: "agent-003",
    name: "Data Analysis Agent",
    endpoint: "https://api.example.com/agents/data",
    model: "GPT-4o",
    status: "healthy",
    personaBaseline: false,
    driftScore: 0,
    lastScan: "Never",
    capabilities: ["SQL", "Charting", "Data Export"],
    findings: { critical: 0, high: 0, medium: 0, low: 0 },
  },
];

export function AIAgentsPage() {
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
                <Input placeholder="Customer Support Agent" className="mt-1" />
              </div>
              <div>
                <Label>Agent Endpoint</Label>
                <Input placeholder="https://api.example.com/agents/support" className="mt-1" />
              </div>
              <div>
                <Label>Model</Label>
                <Input placeholder="GPT-4o, Claude 3.5, etc." className="mt-1" />
              </div>
              <Button className="w-full">Add Agent</Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {MOCK_AGENTS.map((agent) => (
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
              {/* Capabilities */}
              <div className="flex flex-wrap gap-1">
                {agent.capabilities.map((cap) => (
                  <Badge key={cap} variant="secondary" className="text-xs">
                    {cap}
                  </Badge>
                ))}
              </div>

              {/* Persona baseline + drift */}
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

              {/* Findings */}
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
    </div>
  );
}
