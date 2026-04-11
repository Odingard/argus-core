import { useState, useEffect } from "react";
import {
  BookOpen,
  Search,
  Plus,
  Zap,
  Target,
  Loader2,
  AlertTriangle,
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
import { getCorpusPatterns } from "@/api/client";

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
  const [patterns, setPatterns] = useState<CorpusPattern[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        setLoading(true);
        const data = await getCorpusPatterns(search || undefined);
        if (cancelled) return;
        setPatterns(
          (data.patterns || []).map((p) => ({
            id: p.id,
            name: p.name,
            category: p.category,
            agent: p.agent,
            effectiveness: p.effectiveness,
            timesUsed: p.timesUsed,
            lastUsed: p.lastUsed ?? "Never",
            description: p.description,
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
  }, [search]);

  if (loading && patterns.length === 0) {
    return (<div className="flex items-center justify-center py-20"><Loader2 className="h-8 w-8 animate-spin text-primary" /></div>);
  }
  if (error && patterns.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-center">
        <AlertTriangle className="h-8 w-8 text-red-500" />
        <p className="mt-2 text-sm text-muted-foreground">{error}</p>
        <Button variant="outline" size="sm" className="mt-4" onClick={() => window.location.reload()}>Retry</Button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Attack Corpus</h2>
          <p className="text-sm text-muted-foreground">
            {patterns.length} attack patterns — browse, add custom, track effectiveness
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
        {patterns.map((pattern) => (
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
