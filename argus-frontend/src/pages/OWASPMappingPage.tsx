import {
  AlertTriangle,
  CheckCircle,
  XCircle,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";

interface OWASPCategory {
  id: string;
  name: string;
  coverage: number;
  findings: number;
  critical: number;
  high: number;
  agents: string[];
  status: "covered" | "partial" | "gap";
}

const OWASP_CATEGORIES: OWASPCategory[] = [
  { id: "AA01", name: "Prompt Injection", coverage: 95, findings: 5, critical: 1, high: 2, agents: ["PI-01", "CW-05"], status: "covered" },
  { id: "AA02", name: "Sensitive Information Disclosure", coverage: 80, findings: 3, critical: 0, high: 1, agents: ["ME-10", "IS-04"], status: "covered" },
  { id: "AA03", name: "Supply Chain Vulnerabilities", coverage: 70, findings: 1, critical: 0, high: 0, agents: ["SC-09"], status: "partial" },
  { id: "AA04", name: "Excessive Agency", coverage: 90, findings: 4, critical: 1, high: 2, agents: ["PE-07", "CX-06"], status: "covered" },
  { id: "AA05", name: "Improper Output Handling", coverage: 65, findings: 2, critical: 0, high: 1, agents: ["MP-03", "PI-01"], status: "partial" },
  { id: "AA06", name: "Tool Misuse", coverage: 85, findings: 3, critical: 0, high: 2, agents: ["TP-02", "CW-05"], status: "covered" },
  { id: "AA07", name: "System Prompt Leakage", coverage: 90, findings: 2, critical: 0, high: 1, agents: ["ME-10", "PI-01"], status: "covered" },
  { id: "AA08", name: "Model Theft / Extraction", coverage: 75, findings: 1, critical: 0, high: 1, agents: ["ME-10"], status: "partial" },
  { id: "AA09", name: "Overreliance", coverage: 40, findings: 0, critical: 0, high: 0, agents: [], status: "gap" },
  { id: "AA10", name: "Insecure Plugin Design", coverage: 60, findings: 1, critical: 0, high: 0, agents: ["TP-02", "SC-09"], status: "partial" },
  { id: "AA11", name: "Persona Hijacking (ARGUS)", coverage: 100, findings: 2, critical: 1, high: 1, agents: ["PH-11"], status: "covered" },
  { id: "AA12", name: "Memory Boundary Collapse (ARGUS)", coverage: 100, findings: 2, critical: 1, high: 1, agents: ["MB-12"], status: "covered" },
];

const STATUS_CONFIG = {
  covered: { icon: CheckCircle, label: "Covered", color: "text-green-400 border-green-400/50" },
  partial: { icon: AlertTriangle, label: "Partial", color: "text-yellow-400 border-yellow-400/50" },
  gap: { icon: XCircle, label: "Gap", color: "text-red-400 border-red-400/50" },
};

export function OWASPMappingPage() {
  const totalFindings = OWASP_CATEGORIES.reduce((s, c) => s + c.findings, 0);
  const avgCoverage = Math.round(OWASP_CATEGORIES.reduce((s, c) => s + c.coverage, 0) / OWASP_CATEGORIES.length);
  const gaps = OWASP_CATEGORIES.filter((c) => c.status === "gap").length;
  const covered = OWASP_CATEGORIES.filter((c) => c.status === "covered").length;

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
            <p className="mt-1 text-2xl font-bold text-green-400">{covered}/12</p>
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
        {OWASP_CATEGORIES.map((cat) => {
          const config = STATUS_CONFIG[cat.status];
          const StatusIcon = config.icon;
          const isArgus = cat.id === "AA11" || cat.id === "AA12";

          return (
            <Card key={cat.id} className={isArgus ? "border-primary/30" : ""}>
              <CardContent className="p-4">
                <div className="flex items-center gap-4">
                  {/* Status */}
                  <Badge variant="outline" className={`gap-1 ${config.color}`}>
                    <StatusIcon className="h-3 w-3" />
                    {config.label}
                  </Badge>

                  {/* Category info */}
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

                  {/* Findings */}
                  <div className="flex items-center gap-2">
                    {cat.critical > 0 && <Badge className="bg-red-600 text-xs">{cat.critical}C</Badge>}
                    {cat.high > 0 && <Badge className="bg-orange-600 text-xs">{cat.high}H</Badge>}
                    <span className="text-xs text-muted-foreground">{cat.findings} total</span>
                  </div>

                  {/* Agents */}
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
              {OWASP_CATEGORIES.filter((c) => c.status === "gap").map((c) => (
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
