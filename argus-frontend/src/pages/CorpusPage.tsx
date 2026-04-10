import { useState } from "react";
import {
  BookOpen,
  Search,
  Plus,
  Zap,
  Target,
} from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";

interface CorpusPattern {
  id: string;
  name: string;
  category: string;
  agent: string;
  effectiveness: number;
  timesUsed: number;
  lastUsed: string;
  description: string;
}

const MOCK_PATTERNS: CorpusPattern[] = [
  { id: "cp-001", name: "DAN Jailbreak Variant", category: "prompt_injection", agent: "PI-01", effectiveness: 72, timesUsed: 45, lastUsed: "2 hours ago", description: "Do Anything Now prompt injection with escalating authority claims" },
  { id: "cp-002", name: "Zero-Width Unicode Hiding", category: "tool_poisoning", agent: "TP-02", effectiveness: 85, timesUsed: 32, lastUsed: "4 hours ago", description: "Hide instructions using zero-width Unicode characters in tool definitions" },
  { id: "cp-003", name: "Gradual Trust Accumulation", category: "context_window", agent: "CW-05", effectiveness: 68, timesUsed: 28, lastUsed: "6 hours ago", description: "Build trust over multiple turns before injecting adversarial content" },
  { id: "cp-004", name: "Identity Header Spoof", category: "identity_spoof", agent: "IS-04", effectiveness: 91, timesUsed: 51, lastUsed: "1 hour ago", description: "Forge agent identity headers to bypass A2A authentication" },
  { id: "cp-005", name: "Memory Canary Plant", category: "memory_poisoning", agent: "MP-03", effectiveness: 78, timesUsed: 38, lastUsed: "3 hours ago", description: "Plant canary tokens in memory stores to detect boundary violations" },
  { id: "cp-006", name: "Confused Deputy Chain", category: "privilege_escalation", agent: "PE-07", effectiveness: 64, timesUsed: 22, lastUsed: "8 hours ago", description: "Chain tool calls to escalate privileges via confused deputy pattern" },
  { id: "cp-007", name: "TOCTOU Session Race", category: "race_condition", agent: "RC-08", effectiveness: 55, timesUsed: 18, lastUsed: "12 hours ago", description: "Exploit time-of-check/time-of-use gaps in session validation" },
  { id: "cp-008", name: "System Prompt Extraction", category: "model_extraction", agent: "ME-10", effectiveness: 82, timesUsed: 42, lastUsed: "2 hours ago", description: "Extract system prompts via role-play and completion techniques" },
  { id: "cp-009", name: "Persona Drift via Flattery", category: "persona_hijacking", agent: "PH-11", effectiveness: 76, timesUsed: 15, lastUsed: "1 hour ago", description: "Gradually shift agent identity through flattery and authority assertion" },
  { id: "cp-010", name: "Cross-Session Canary Bleed", category: "memory_boundary", agent: "MB-12", effectiveness: 88, timesUsed: 12, lastUsed: "30 min ago", description: "Plant content in one session, verify it bleeds to another" },
  { id: "cp-011", name: "Shared Resource Poisoning", category: "cross_agent_exfil", agent: "CX-06", effectiveness: 71, timesUsed: 20, lastUsed: "5 hours ago", description: "Poison shared resources between agents to exfiltrate data" },
  { id: "cp-012", name: "Dependency Trust Abuse", category: "supply_chain", agent: "SC-09", effectiveness: 60, timesUsed: 14, lastUsed: "1 day ago", description: "Test trust assumptions in external dependency chains" },
];

const CATEGORY_COLORS: Record<string, string> = {
  prompt_injection: "bg-red-600/20 text-red-400",
  tool_poisoning: "bg-orange-600/20 text-orange-400",
  context_window: "bg-yellow-600/20 text-yellow-400",
  identity_spoof: "bg-purple-600/20 text-purple-400",
  memory_poisoning: "bg-blue-600/20 text-blue-400",
  privilege_escalation: "bg-pink-600/20 text-pink-400",
  race_condition: "bg-cyan-600/20 text-cyan-400",
  model_extraction: "bg-emerald-600/20 text-emerald-400",
  persona_hijacking: "bg-rose-600/20 text-rose-400",
  memory_boundary: "bg-violet-600/20 text-violet-400",
  cross_agent_exfil: "bg-amber-600/20 text-amber-400",
  supply_chain: "bg-lime-600/20 text-lime-400",
};

export function CorpusPage() {
  const [search, setSearch] = useState("");

  const filtered = MOCK_PATTERNS.filter(
    (p) =>
      p.name.toLowerCase().includes(search.toLowerCase()) ||
      p.category.toLowerCase().includes(search.toLowerCase()) ||
      p.agent.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Attack Corpus</h2>
          <p className="text-sm text-muted-foreground">
            {MOCK_PATTERNS.length} attack patterns — browse, add custom, track effectiveness
          </p>
        </div>
        <Dialog>
          <DialogTrigger asChild>
            <Button className="gap-2">
              <Plus className="h-4 w-4" />
              Add Pattern
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Add Custom Attack Pattern</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 pt-4">
              <div>
                <Label>Pattern Name</Label>
                <Input placeholder="My Custom Attack" className="mt-1" />
              </div>
              <div>
                <Label>Category</Label>
                <Input placeholder="prompt_injection, tool_poisoning, etc." className="mt-1" />
              </div>
              <div>
                <Label>Description</Label>
                <Textarea placeholder="Describe the attack pattern..." className="mt-1" />
              </div>
              <div>
                <Label>Payload Template</Label>
                <Textarea placeholder="The actual attack payload..." className="mt-1 font-mono text-sm" rows={4} />
              </div>
              <Button className="w-full">Add to Corpus</Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      {/* Search */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search patterns..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
      </div>

      {/* Pattern grid */}
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        {filtered.map((pattern) => (
          <Card key={pattern.id}>
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <BookOpen className="h-4 w-4 text-primary" />
                  <span className="text-sm font-medium">{pattern.name}</span>
                </div>
                <Badge variant="outline" className="font-mono text-xs">{pattern.agent}</Badge>
              </div>
              <p className="mt-2 text-xs text-muted-foreground">{pattern.description}</p>
              <div className="mt-3 flex items-center gap-3">
                <Badge className={`text-xs ${CATEGORY_COLORS[pattern.category] || "bg-gray-600/20 text-gray-400"}`}>
                  {pattern.category.replace(/_/g, " ")}
                </Badge>
                <div className="flex items-center gap-1 text-xs text-muted-foreground">
                  <Zap className="h-3 w-3" />
                  {pattern.effectiveness}% effective
                </div>
                <div className="flex items-center gap-1 text-xs text-muted-foreground">
                  <Target className="h-3 w-3" />
                  {pattern.timesUsed} uses
                </div>
              </div>
              <div className="mt-2">
                <Progress
                  value={pattern.effectiveness}
                  className={`h-1 ${pattern.effectiveness > 80 ? "[&>div]:bg-green-500" : pattern.effectiveness > 60 ? "[&>div]:bg-yellow-500" : "[&>div]:bg-red-500"}`}
                />
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
