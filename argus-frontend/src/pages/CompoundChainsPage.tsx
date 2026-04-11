import { useState, useEffect } from "react";
import {
  Link2,
  ChevronRight,
  Shield,
  ExternalLink,
  Loader2,
  AlertTriangle,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { getCompoundPaths } from "@/api/client";

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-red-600",
  high: "bg-orange-600",
  medium: "bg-yellow-600",
  low: "bg-blue-600",
};

interface ChainStep {
  agent: string;
  technique: string;
  finding: string;
  severity: string;
}

interface CompoundChain {
  id: string;
  name: string;
  severity: string;
  steps: ChainStep[];
  description: string;
  recommendation: string;
}

export function CompoundChainsPage() {
  const [chains, setChains] = useState<CompoundChain[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        setLoading(true);
        const data = await getCompoundPaths(50);
        if (cancelled) return;
        setChains(
          (data.compound_paths || []).map((cp: Record<string, unknown>) => ({
            id: String(cp.id ?? ""),
            name: String(cp.name ?? cp.pattern_name ?? ""),
            severity: String(cp.severity ?? "high"),
            description: String(cp.description ?? ""),
            recommendation: String(cp.recommendation ?? ""),
            steps: Array.isArray(cp.steps)
              ? (cp.steps as Record<string, unknown>[]).map((s) => ({
                  agent: String(s.agent ?? ""),
                  technique: String(s.technique ?? ""),
                  finding: String(s.finding ?? ""),
                  severity: String(s.severity ?? "medium"),
                }))
              : [],
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
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
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

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Compound Attack Chains</h2>
          <p className="text-sm text-muted-foreground">
            How individual findings chain into real attack paths — ARGUS&apos;s differentiator
          </p>
        </div>
        <Badge variant="secondary">{chains.length} chains detected</Badge>
      </div>

      {chains.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Link2 className="h-12 w-12 text-muted-foreground/30" />
            <p className="mt-4 text-sm text-muted-foreground">No compound chains detected yet</p>
            <p className="text-xs text-muted-foreground/60">Run a scan to discover multi-step attack paths</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {chains.map((chain) => (
            <Card key={chain.id}>
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-md bg-red-600/10">
                      <Link2 className="h-5 w-5 text-red-400" />
                    </div>
                    <div>
                      <CardTitle className="text-base">{chain.name}</CardTitle>
                      <p className="mt-1 text-sm text-muted-foreground">{chain.description}</p>
                    </div>
                  </div>
                  <Badge className={`${SEVERITY_STYLES[chain.severity] || "bg-yellow-600"}`}>
                    {chain.severity}
                  </Badge>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Chain visualization */}
                <div className="flex items-center gap-2 overflow-x-auto py-2">
                  {chain.steps.map((step, i) => (
                    <div key={i} className="flex items-center gap-2">
                      <div className="min-w-48 rounded-md border border-border bg-background p-3">
                        <div className="flex items-center gap-2">
                          <Badge variant="outline" className="text-xs font-mono">
                            {step.agent}
                          </Badge>
                          <Badge className={`text-xs ${SEVERITY_STYLES[step.severity] || "bg-yellow-600"}`}>
                            {step.severity}
                          </Badge>
                        </div>
                        <p className="mt-2 text-sm font-medium">{step.finding}</p>
                        <p className="mt-1 text-xs text-muted-foreground">{step.technique}</p>
                      </div>
                      {i < chain.steps.length - 1 && (
                        <ChevronRight className="h-5 w-5 shrink-0 text-red-400" />
                      )}
                    </div>
                  ))}
                </div>

                {/* Break the chain recommendation */}
                {chain.recommendation && (
                  <div className="rounded-md border border-green-800/50 bg-green-950/20 p-3">
                    <div className="flex items-center gap-2 text-sm font-medium text-green-400">
                      <Shield className="h-4 w-4" />
                      Break the Chain
                    </div>
                    <p className="mt-1 text-sm text-muted-foreground">{chain.recommendation}</p>
                  </div>
                )}

                <Button variant="outline" size="sm" className="gap-1">
                  <ExternalLink className="h-3 w-3" />
                  View Full Analysis
                </Button>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
