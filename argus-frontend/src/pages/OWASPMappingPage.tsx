import { useState, useEffect } from "react";
import {
  AlertTriangle,
  CheckCircle,
  XCircle,
  Loader2,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { getOWASPCoverage } from "@/api/client";

interface OWASPCategory {
  id: string;
  name: string;
  coverage: number;
  findings: number;
  critical: number;
  high: number;
  agents: string[];
  status: string;
}

const STATUS_CONFIG: Record<string, { icon: React.ElementType; label: string; color: string }> = {
  covered: { icon: CheckCircle, label: "Covered", color: "text-green-400 border-green-400/50" },
  partial: { icon: AlertTriangle, label: "Partial", color: "text-yellow-400 border-yellow-400/50" },
  gap: { icon: XCircle, label: "Gap", color: "text-red-400 border-red-400/50" },
};

export function OWASPMappingPage() {
  const [categories, setCategories] = useState<OWASPCategory[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        setLoading(true);
        const data = await getOWASPCoverage();
        if (cancelled) return;
        setCategories(
          (data.categories || []).map((c) => ({
            id: c.id,
            name: c.name,
            coverage: c.coverage,
            findings: c.findings,
            critical: c.critical,
            high: c.high,
            agents: c.agents,
            status: c.status,
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

  const totalFindings = categories.reduce((s, c) => s + c.findings, 0);
  const avgCoverage = categories.length > 0 ? Math.round(categories.reduce((s, c) => s + c.coverage, 0) / categories.length) : 0;
  const gaps = categories.filter((c) => c.status === "gap").length;
  const covered = categories.filter((c) => c.status === "covered").length;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">OWASP Mapping</h2>
          <p className="text-sm text-muted-foreground">
            Coverage against OWASP Agentic AI Top 10 + ARGUS proprietary categories
          </p>
        </div>
      </div>

      {/* Summary stats */}
      <div className="grid grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4">
            <p className="text-sm text-muted-foreground">Avg Coverage</p>
            <p className="mt-1 text-2xl font-bold">{avgCoverage}%</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <p className="text-sm text-muted-foreground">Categories Covered</p>
            <p className="mt-1 text-2xl font-bold text-green-400">{covered}/{categories.length}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <p className="text-sm text-muted-foreground">Coverage Gaps</p>
            <p className="mt-1 text-2xl font-bold text-red-400">{gaps}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <p className="text-sm text-muted-foreground">Total Findings</p>
            <p className="mt-1 text-2xl font-bold">{totalFindings}</p>
          </CardContent>
        </Card>
      </div>

      {/* Category list */}
      <div className="space-y-3">
        {categories.map((cat) => {
          const config = STATUS_CONFIG[cat.status] || STATUS_CONFIG.gap;
          const StatusIcon = config.icon;
          const isArgus = cat.id === "AA11" || cat.id === "AA12";

          return (
            <Card key={cat.id} className={isArgus ? "border-primary/30" : ""}>
              <CardContent className="p-4">
                <div className="flex items-center gap-4">
                  <Badge variant="outline" className={`gap-1 ${config.color}`}>
                    <StatusIcon className="h-3 w-3" />
                    {config.label}
                  </Badge>

                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm font-bold text-primary">{cat.id}</span>
                      <span className="text-sm font-medium">{cat.name}</span>
                      {isArgus && (
                        <Badge className="bg-primary/20 text-primary text-xs">ARGUS Proprietary</Badge>
                      )}
                    </div>
                    <div className="mt-2 flex items-center gap-3">
                      <div className="flex-1 max-w-xs">
                        <Progress
                          value={cat.coverage}
                          className={`h-1.5 ${
                            cat.coverage > 80 ? "[&>div]:bg-green-500" :
                            cat.coverage > 50 ? "[&>div]:bg-yellow-500" :
                            "[&>div]:bg-red-500"
                          }`}
                        />
                      </div>
                      <span className="text-xs text-muted-foreground">{cat.coverage}%</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    {cat.critical > 0 && <Badge className="bg-red-600 text-xs">{cat.critical}C</Badge>}
                    {cat.high > 0 && <Badge className="bg-orange-600 text-xs">{cat.high}H</Badge>}
                    <span className="text-xs text-muted-foreground">{cat.findings} total</span>
                  </div>

                  <div className="flex items-center gap-1">
                    {cat.agents.map((a) => (
                      <Badge key={a} variant="secondary" className="text-xs font-mono">
                        {a}
                      </Badge>
                    ))}
                    {cat.agents.length === 0 && (
                      <span className="text-xs text-red-400">No agent coverage</span>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Gap analysis note */}
      <Card className="border-red-800/50">
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-sm font-medium text-red-400">
            <AlertTriangle className="h-4 w-4" />
            Gap Analysis
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            {gaps === 0
              ? "All OWASP Agentic AI categories are covered by at least one ARGUS agent."
              : `${gaps} category(s) have no dedicated ARGUS agent coverage. Consider adding targeted attack techniques for these categories.`}
          </p>
          {gaps > 0 && (
            <div className="mt-2 space-y-1">
              {categories.filter((c) => c.status === "gap").map((c) => (
                <p key={c.id} className="text-sm">
                  <span className="font-mono text-red-400">{c.id}</span> — {c.name}
                </p>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
