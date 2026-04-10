import {
  GitBranch,
  Plus,
  ArrowRight,
  Shield,
  AlertTriangle,
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

interface Pipeline {
  id: string;
  name: string;
  agents: { name: string; trust: "high" | "medium" | "low" }[];
  trustBoundaries: number;
  lastScan: string;
  findings: number;
  criticalPaths: number;
}

const MOCK_PIPELINES: Pipeline[] = [
  {
    id: "pipe-001",
    name: "Customer Intake Pipeline",
    agents: [
      { name: "Triage Agent", trust: "high" },
      { name: "Router Agent", trust: "medium" },
      { name: "Support Agent", trust: "high" },
      { name: "Escalation Agent", trust: "low" },
    ],
    trustBoundaries: 3,
    lastScan: "6 hours ago",
    findings: 4,
    criticalPaths: 1,
  },
  {
    id: "pipe-002",
    name: "Code Review Pipeline",
    agents: [
      { name: "PR Analyzer", trust: "high" },
      { name: "Security Scanner", trust: "high" },
      { name: "Reviewer Agent", trust: "medium" },
    ],
    trustBoundaries: 2,
    lastScan: "1 day ago",
    findings: 2,
    criticalPaths: 0,
  },
];

const TRUST_COLORS = {
  high: "text-green-400 border-green-400/50",
  medium: "text-yellow-400 border-yellow-400/50",
  low: "text-red-400 border-red-400/50",
};

export function PipelinesPage() {
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
                <Input placeholder="Customer Intake Pipeline" className="mt-1" />
              </div>
              <div>
                <Label>Description</Label>
                <Input placeholder="Describe the pipeline flow" className="mt-1" />
              </div>
              <Button className="w-full">Add Pipeline</Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <div className="space-y-4">
        {MOCK_PIPELINES.map((pipeline) => (
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
              {/* Agent flow visualization */}
              <div className="flex items-center gap-2 overflow-x-auto py-2">
                {pipeline.agents.map((agent, i) => (
                  <div key={agent.name} className="flex items-center gap-2">
                    <div className="rounded-md border border-border bg-background p-3 text-center min-w-28">
                      <p className="text-sm font-medium">{agent.name}</p>
                      <Badge variant="outline" className={`mt-1 text-xs ${TRUST_COLORS[agent.trust]}`}>
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
              <p className="mt-3 text-xs text-muted-foreground">Last scan: {pipeline.lastScan}</p>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
