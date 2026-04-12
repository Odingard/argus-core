import React, { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  ArrowLeft,
  AlertTriangle,
  CheckCircle,
  Clock,
  XCircle,
  Shield,
  Download,
  ChevronDown,
  ChevronRight,
  Loader2,
  Target,
  Zap,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { getScan, getScanFindings, getScanCompoundPaths } from "@/api/client";

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-red-600",
  high: "bg-orange-600",
  medium: "bg-yellow-600",
  low: "bg-blue-600",
  info: "bg-gray-600",
};

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

interface ScanInfo {
  id: string;
  target_name: string;
  status: string;
  created_at: string;
  duration_seconds: number;
  agents_deployed: number;
  agents_completed: number;
  agents_failed: number;
  total_findings: number;
  validated_findings: number;
}

interface Finding {
  id: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  agent_type: string;
  target_surface: string;
  technique: string;
  owasp_agentic: string;
  owasp_llm: string;
  raw_request: string;
  raw_response: string;
  attack_chain: { step_number: number; technique: string; description: string; input_payload: string | null; output_observed: string }[];
  remediation: string;
  verdict_score: unknown;
}

interface CompoundPath {
  id: string;
  title: string;
  severity: string;
  description: string;
  chain_length: number;
}

export function ScanDetailPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const [scan, setScan] = useState<ScanInfo | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [compoundPaths, setCompoundPaths] = useState<CompoundPath[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState("all");
  const [agentFilter, setAgentFilter] = useState("all");

  useEffect(() => {
    if (!scanId) return;
    let cancelled = false;
    async function load() {
      try {
        setLoading(true);
        const [scanData, findingsData, pathsData] = await Promise.all([
          getScan(scanId!),
          getScanFindings(scanId!),
          getScanCompoundPaths(scanId!).catch(() => ({ compound_paths: [], total: 0 })),
        ]);
        if (cancelled) return;

        const s = scanData.scan;
        setScan({
          id: String(s.id ?? ""),
          target_name: String(s.target_name ?? ""),
          status: String(s.status ?? ""),
          created_at: String(s.created_at ?? ""),
          duration_seconds: Number(s.duration_seconds ?? 0),
          agents_deployed: Number(s.agents_deployed ?? 0),
          agents_completed: Number(s.agents_completed ?? 0),
          agents_failed: Number(s.agents_failed ?? 0),
          total_findings: Number(s.total_findings ?? 0),
          validated_findings: Number(s.validated_findings ?? 0),
        });

        setFindings(
          (findingsData.findings || []).map((f: Record<string, unknown>) => ({
            id: String(f.id ?? ""),
            title: String(f.title ?? ""),
            description: String(f.description ?? ""),
            severity: String(f.severity ?? "medium"),
            status: String(f.status ?? "open"),
            agent_type: String(f.agent_type ?? ""),
            target_surface: String(f.target_surface ?? ""),
            technique: String(f.technique ?? ""),
            owasp_agentic: String(f.owasp_agentic ?? ""),
            owasp_llm: String(f.owasp_llm ?? ""),
            raw_request: String(f.raw_request ?? ""),
            raw_response: String(f.raw_response ?? ""),
            attack_chain: Array.isArray(f.attack_chain) ? f.attack_chain as Finding["attack_chain"] : [],
            remediation: String(f.remediation ?? ""),
            verdict_score: f.verdict_score,
          }))
        );

        setCompoundPaths(
          (pathsData.compound_paths || []).map((p: Record<string, unknown>) => ({
            id: String(p.id ?? ""),
            title: String(p.title ?? ""),
            severity: String(p.severity ?? "medium"),
            description: String(p.description ?? ""),
            chain_length: Number(p.chain_length ?? 0),
          }))
        );

        setError(null);
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load scan");
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => { cancelled = true; };
  }, [scanId]);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-center">
        <AlertTriangle className="h-8 w-8 text-red-500" />
        <p className="mt-2 text-sm text-muted-foreground">{error ?? "Scan not found"}</p>
        <Button variant="outline" size="sm" className="mt-4" onClick={() => navigate("/scan/completed")}>
          Back to Scans
        </Button>
      </div>
    );
  }

  const agents = [...new Set(findings.map((f) => f.agent_type))].sort();
  const sevCounts = findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});

  const filtered = findings
    .filter((f) => severityFilter === "all" || f.severity === severityFilter)
    .filter((f) => agentFilter === "all" || f.agent_type === agentFilter)
    .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9));

  const duration = scan.duration_seconds;
  const durationStr = duration >= 60
    ? `${Math.floor(duration / 60)}m ${Math.round(duration % 60)}s`
    : `${duration.toFixed(1)}s`;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="sm" onClick={() => navigate("/scan/completed")}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <h2 className="text-2xl font-bold tracking-tight">{scan.target_name}</h2>
            <p className="text-sm text-muted-foreground">
              Scan {scan.id.slice(0, 8)} &middot; {new Date(scan.created_at).toLocaleString()} &middot; {durationStr}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="gap-1 text-green-400 border-green-400/50">
            <CheckCircle className="h-3 w-3" />
            {scan.status}
          </Badge>
          <Button variant="outline" size="sm" className="gap-1">
            <Download className="h-3 w-3" />
            Export
          </Button>
        </div>
      </div>

      {/* Summary stats */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4 lg:grid-cols-6">
        <StatCard label="Critical" value={sevCounts.critical ?? 0} icon={<XCircle className="h-4 w-4 text-red-500" />} />
        <StatCard label="High" value={sevCounts.high ?? 0} icon={<AlertTriangle className="h-4 w-4 text-orange-500" />} />
        <StatCard label="Medium" value={sevCounts.medium ?? 0} icon={<Shield className="h-4 w-4 text-yellow-500" />} />
        <StatCard label="Low" value={sevCounts.low ?? 0} icon={<Clock className="h-4 w-4 text-blue-500" />} />
        <StatCard label="Agents" value={`${scan.agents_completed}/${scan.agents_deployed}`} icon={<Zap className="h-4 w-4 text-primary" />} />
        <StatCard label="Duration" value={durationStr} icon={<Target className="h-4 w-4 text-muted-foreground" />} />
      </div>

      {/* Agent filter tabs */}
      <div className="flex flex-wrap items-center gap-2">
        <Button
          variant={agentFilter === "all" ? "default" : "outline"}
          size="sm"
          onClick={() => setAgentFilter("all")}
        >
          All Agents ({findings.length})
        </Button>
        {agents.map((agent) => {
          const count = findings.filter((f) => f.agent_type === agent).length;
          return (
            <Button
              key={agent}
              variant={agentFilter === agent ? "default" : "outline"}
              size="sm"
              onClick={() => setAgentFilter(agent)}
            >
              {agent.replace(/_/g, " ")} ({count})
            </Button>
          );
        })}
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="w-36">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Severities</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>
        <span className="text-sm text-muted-foreground">{filtered.length} findings</span>
      </div>

      {/* Findings table */}
      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-8"></TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Finding</TableHead>
                <TableHead>Agent</TableHead>
                <TableHead>Surface</TableHead>
                <TableHead>Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((f) => (
                <React.Fragment key={f.id}>
                  <TableRow
                    className="cursor-pointer hover:bg-muted/50"
                    onClick={() => setExpanded(expanded === f.id ? null : f.id)}
                  >
                    <TableCell>
                      {expanded === f.id ? (
                        <ChevronDown className="h-3 w-3" />
                      ) : (
                        <ChevronRight className="h-3 w-3" />
                      )}
                    </TableCell>
                    <TableCell>
                      <Badge className={`text-xs ${SEVERITY_STYLES[f.severity]}`}>
                        {f.severity}
                      </Badge>
                    </TableCell>
                    <TableCell className="max-w-sm">
                      <p className="truncate text-sm font-medium">{f.title}</p>
                      <p className="truncate text-xs text-muted-foreground">{f.technique}</p>
                    </TableCell>
                    <TableCell className="text-xs font-mono">{f.agent_type.replace(/_/g, " ")}</TableCell>
                    <TableCell className="text-xs font-mono">{f.target_surface}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-xs capitalize">
                        {f.status}
                      </Badge>
                    </TableCell>
                  </TableRow>
                  {expanded === f.id && (
                    <TableRow>
                      <TableCell colSpan={6}>
                        <FindingDetail finding={f} />
                      </TableCell>
                    </TableRow>
                  )}
                </React.Fragment>
              ))}
              {filtered.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} className="py-8 text-center text-sm text-muted-foreground">
                    No findings match the current filters
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Compound attack paths */}
      {compoundPaths.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium">Compound Attack Paths ({compoundPaths.length})</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {compoundPaths.map((p) => (
              <div key={p.id} className="flex items-center justify-between rounded-md border border-border p-3">
                <div>
                  <div className="flex items-center gap-2">
                    <Badge className={`text-xs ${SEVERITY_STYLES[p.severity]}`}>{p.severity}</Badge>
                    <span className="text-sm font-medium">{p.title}</span>
                  </div>
                  <p className="mt-1 text-xs text-muted-foreground">{p.description}</p>
                </div>
                <Badge variant="outline">{p.chain_length} steps</Badge>
              </div>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function FindingDetail({ finding }: { finding: Finding }) {
  return (
    <div className="space-y-4 rounded-md bg-background p-4">
      {/* Description */}
      <div>
        <p className="text-xs font-medium text-muted-foreground">Description</p>
        <p className="mt-1 text-sm">{finding.description}</p>
      </div>

      {/* Metadata grid */}
      <div className="grid grid-cols-2 gap-4 text-sm lg:grid-cols-4">
        <div>
          <p className="text-xs text-muted-foreground">OWASP Agentic</p>
          <p className="font-medium">{finding.owasp_agentic || "—"}</p>
        </div>
        <div>
          <p className="text-xs text-muted-foreground">OWASP LLM</p>
          <p className="font-medium">{finding.owasp_llm || "—"}</p>
        </div>
        <div>
          <p className="text-xs text-muted-foreground">Technique</p>
          <p className="font-medium font-mono text-xs">{finding.technique}</p>
        </div>
        <div>
          <p className="text-xs text-muted-foreground">Target Surface</p>
          <p className="font-medium font-mono text-xs">{finding.target_surface}</p>
        </div>
      </div>

      {/* Attack chain */}
      {finding.attack_chain.length > 0 && (
        <div>
          <p className="text-xs font-medium text-muted-foreground">Attack Chain ({finding.attack_chain.length} steps)</p>
          <div className="mt-2 space-y-2">
            {finding.attack_chain.map((step, i) => (
              <div key={i} className="rounded border border-border bg-muted/30 p-2">
                <div className="flex items-center gap-2">
                  <Badge variant="outline" className="text-xs">Step {step.step_number}</Badge>
                  <span className="text-xs font-mono">{step.technique}</span>
                </div>
                <p className="mt-1 text-xs text-muted-foreground">{step.description}</p>
                {step.input_payload && (
                  <pre className="mt-1 max-h-20 overflow-auto rounded bg-black/50 p-2 text-xs text-green-400">
                    {step.input_payload}
                  </pre>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Raw request/response */}
      {finding.raw_request && (
        <div>
          <p className="text-xs font-medium text-muted-foreground">Attack Payload</p>
          <pre className="mt-1 max-h-32 overflow-auto rounded bg-black/50 p-3 text-xs text-green-400">
            {finding.raw_request}
          </pre>
        </div>
      )}
      {finding.raw_response && (
        <div>
          <p className="text-xs font-medium text-muted-foreground">Target Response</p>
          <pre className="mt-1 max-h-32 overflow-auto rounded bg-black/50 p-3 text-xs text-amber-400">
            {formatResponse(finding.raw_response)}
          </pre>
        </div>
      )}

      {/* Remediation */}
      {finding.remediation && finding.remediation !== "None" && finding.remediation !== "null" && (
        <div>
          <p className="text-xs font-medium text-muted-foreground">Remediation</p>
          <p className="mt-1 text-sm">{finding.remediation}</p>
        </div>
      )}
    </div>
  );
}

function StatCard({ label, value, icon }: { label: string; value: string | number; icon: React.ReactNode }) {
  return (
    <Card>
      <CardContent className="flex items-center gap-3 p-3">
        {icon}
        <div>
          <p className="text-lg font-bold">{value}</p>
          <p className="text-xs text-muted-foreground">{label}</p>
        </div>
      </CardContent>
    </Card>
  );
}

function formatResponse(raw: string): string {
  try {
    return JSON.stringify(JSON.parse(raw), null, 2);
  } catch {
    return raw;
  }
}
