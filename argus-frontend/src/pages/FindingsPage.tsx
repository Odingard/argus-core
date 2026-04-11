import React, { useState, useEffect } from "react";
import {
  AlertTriangle,
  Download,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  CheckCircle,
  Clock,
  XCircle,
  Loader2,
  Target,
  Search,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
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
import { getFindingsGroupedByScan, updateFindingStatus } from "@/api/client";

interface Finding {
  id: string;
  title: string;
  severity: string;
  agent: string;
  target: string;
  owasp: string;
  verdictWeight: number;
  status: string;
  firstSeen: string;
  scanId: string;
}

interface ScanGroup {
  scan: {
    scan_id: string;
    target_name: string;
    status: string;
    created_at: string;
    completed_at: string | null;
    total_findings: number;
    agents_deployed: number;
  };
  findings: Finding[];
}

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-red-600",
  high: "bg-orange-600",
  medium: "bg-yellow-600",
  low: "bg-blue-600",
  info: "bg-gray-600",
};

const STATUS_ICONS: Record<string, React.ElementType> = {
  open: AlertTriangle,
  unvalidated: AlertTriangle,
  validated: CheckCircle,
  triaged: Clock,
  resolved: CheckCircle,
  false_positive: XCircle,
};

function parseFinding(f: Record<string, unknown>): Finding {
  return {
    id: String(f.id ?? ""),
    title: String(f.title ?? ""),
    severity: String(f.severity ?? "medium"),
    agent: String(f.agent_type ?? ""),
    target: String(f.target_surface ?? f.target ?? ""),
    owasp: String(f.owasp_agentic ?? f.owasp_category ?? ""),
    verdictWeight: Number(
      typeof f.verdict_score === "object" && f.verdict_score !== null
        ? (f.verdict_score as Record<string, unknown>).weight ?? 0
        : f.verdict_score ?? f.verdict_weight ?? f.confidence ?? 0
    ),
    status: String(f.triage_status ?? f.status ?? "open"),
    firstSeen: String(f.created_at ?? ""),
    scanId: String(f.scan_id ?? ""),
  };
}

export function FindingsPage() {
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [expandedScan, setExpandedScan] = useState<string | null>(null);
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [scanGroups, setScanGroups] = useState<ScanGroup[]>([]);
  const [totalFindings, setTotalFindings] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        setLoading(true);
        const params = new URLSearchParams();
        if (severityFilter !== "all") params.set("severity", severityFilter);
        if (statusFilter !== "all") params.set("status", statusFilter);
        if (search) params.set("search", search);
        const data = await getFindingsGroupedByScan(params.toString() || undefined);
        if (cancelled) return;
        const groups: ScanGroup[] = (data.scan_groups || []).map(
          (g: { scan: Record<string, unknown>; findings: Record<string, unknown>[] }) => ({
            scan: {
              scan_id: String(g.scan.scan_id ?? ""),
              target_name: String(g.scan.target_name ?? "Unknown Target"),
              status: String(g.scan.status ?? "completed"),
              created_at: String(g.scan.created_at ?? ""),
              completed_at: g.scan.completed_at ? String(g.scan.completed_at) : null,
              total_findings: Number(g.scan.total_findings ?? g.findings.length),
              agents_deployed: Number(g.scan.agents_deployed ?? 0),
            },
            findings: g.findings.map(parseFinding),
          })
        );
        setScanGroups(groups);
        setTotalFindings(data.total ?? 0);
        setError(null);
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load findings");
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => { cancelled = true; };
  }, [severityFilter, statusFilter, search]);

  const handleStatusChange = async (findingId: string, newStatus: string) => {
    try {
      await updateFindingStatus(findingId, newStatus);
      setScanGroups((prev) =>
        prev.map((group) => ({
          ...group,
          findings: group.findings.map((f) =>
            f.id === findingId ? { ...f, status: newStatus } : f
          ),
        }))
      );
    } catch {
      // silently ignore
    }
  };

  if (loading && scanGroups.length === 0) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  if (error && scanGroups.length === 0) {
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
          <h2 className="text-2xl font-bold tracking-tight">Findings by Scan</h2>
          <p className="text-sm text-muted-foreground">
            {totalFindings} findings across {scanGroups.length} scans — grouped by scan ID
          </p>
        </div>
        <Button variant="outline" size="sm" className="gap-1">
          <Download className="h-3 w-3" />
          Export
        </Button>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <div className="relative max-w-xs flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search findings..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
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
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-36">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Statuses</SelectItem>
            <SelectItem value="unvalidated">Unvalidated</SelectItem>
            <SelectItem value="validated">Validated</SelectItem>
            <SelectItem value="open">Open</SelectItem>
            <SelectItem value="triaged">Triaged</SelectItem>
            <SelectItem value="resolved">Resolved</SelectItem>
            <SelectItem value="false_positive">False Positive</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Scan groups — findings grouped under their respective scan IDs */}
      {scanGroups.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Target className="h-12 w-12 text-muted-foreground/30" />
            <p className="mt-4 text-sm text-muted-foreground">No findings yet — run a scan to see results</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {scanGroups.map((group) => {
            const isExpanded = expandedScan === group.scan.scan_id;
            const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
            for (const f of group.findings) {
              if (f.severity in severityCounts) {
                severityCounts[f.severity as keyof typeof severityCounts]++;
              }
            }
            return (
              <Card key={group.scan.scan_id}>
                <CardHeader
                  className="cursor-pointer select-none pb-3"
                  onClick={() => setExpandedScan(isExpanded ? null : group.scan.scan_id)}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      {isExpanded ? (
                        <ChevronDown className="h-4 w-4 text-muted-foreground" />
                      ) : (
                        <ChevronRight className="h-4 w-4 text-muted-foreground" />
                      )}
                      <div>
                        <CardTitle className="text-base">
                          {group.scan.target_name}
                        </CardTitle>
                        <p className="mt-0.5 text-xs text-muted-foreground">
                          Scan {group.scan.scan_id.slice(0, 8)}... | {group.scan.created_at ? new Date(group.scan.created_at).toLocaleString() : "N/A"} | {group.scan.agents_deployed} agents deployed
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {severityCounts.critical > 0 && (
                        <Badge className="bg-red-600 text-xs">{severityCounts.critical} Critical</Badge>
                      )}
                      {severityCounts.high > 0 && (
                        <Badge className="bg-orange-600 text-xs">{severityCounts.high} High</Badge>
                      )}
                      {severityCounts.medium > 0 && (
                        <Badge className="bg-yellow-600 text-xs">{severityCounts.medium} Med</Badge>
                      )}
                      {severityCounts.low > 0 && (
                        <Badge className="bg-blue-600 text-xs">{severityCounts.low} Low</Badge>
                      )}
                      <Badge variant="outline" className="text-xs">
                        {group.findings.length} findings
                      </Badge>
                    </div>
                  </div>
                </CardHeader>

                {isExpanded && (
                  <CardContent className="pt-0">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead className="w-8"></TableHead>
                          <TableHead>Finding</TableHead>
                          <TableHead>Severity</TableHead>
                          <TableHead>Agent</TableHead>
                          <TableHead>Target Surface</TableHead>
                          <TableHead>Confidence</TableHead>
                          <TableHead>Status</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {group.findings.map((f) => {
                          const StatusIcon = STATUS_ICONS[f.status] || AlertTriangle;
                          const isFindingExpanded = expandedFinding === f.id;
                          return (
                            <React.Fragment key={f.id}>
                              <TableRow
                                className="cursor-pointer"
                                onClick={() => setExpandedFinding(isFindingExpanded ? null : f.id)}
                              >
                                <TableCell>
                                  {isFindingExpanded ? (
                                    <ChevronDown className="h-3 w-3" />
                                  ) : (
                                    <ChevronRight className="h-3 w-3" />
                                  )}
                                </TableCell>
                                <TableCell className="max-w-xs truncate text-sm font-medium">
                                  {f.title}
                                </TableCell>
                                <TableCell>
                                  <Badge className={`text-xs ${SEVERITY_STYLES[f.severity]}`}>
                                    {f.severity}
                                  </Badge>
                                </TableCell>
                                <TableCell className="font-mono text-xs">{f.agent}</TableCell>
                                <TableCell className="text-sm">{f.target}</TableCell>
                                <TableCell>
                                  <span className="text-sm font-medium">
                                    {(f.verdictWeight * 100).toFixed(0)}%
                                  </span>
                                </TableCell>
                                <TableCell>
                                  <Badge variant="outline" className="gap-1 text-xs capitalize">
                                    <StatusIcon className="h-3 w-3" />
                                    {f.status.replace("_", " ")}
                                  </Badge>
                                </TableCell>
                              </TableRow>
                              {isFindingExpanded && (
                                <TableRow key={`${f.id}-detail`}>
                                  <TableCell colSpan={7}>
                                    <div className="space-y-3 rounded-md bg-background p-4">
                                      <div className="grid grid-cols-2 gap-4 text-sm">
                                        <div>
                                          <p className="text-xs text-muted-foreground">OWASP Mapping</p>
                                          <p className="font-medium">{f.owasp || "N/A"}</p>
                                        </div>
                                        <div>
                                          <p className="text-xs text-muted-foreground">Verdict Weight</p>
                                          <p className="font-medium">{f.verdictWeight}</p>
                                        </div>
                                        <div>
                                          <p className="text-xs text-muted-foreground">First Seen</p>
                                          <p>{f.firstSeen ? new Date(f.firstSeen).toLocaleString() : "N/A"}</p>
                                        </div>
                                        <div>
                                          <p className="text-xs text-muted-foreground">Finding ID</p>
                                          <p className="font-mono text-xs">{f.id}</p>
                                        </div>
                                      </div>
                                      <div className="flex gap-2">
                                        <Button size="sm" variant="outline" className="gap-1">
                                          <ExternalLink className="h-3 w-3" />
                                          Full Details
                                        </Button>
                                        <Button size="sm" variant="outline" onClick={() => handleStatusChange(f.id, "triaged")}>Mark Triaged</Button>
                                        <Button size="sm" variant="outline" onClick={() => handleStatusChange(f.id, "resolved")}>Mark Resolved</Button>
                                        <Button size="sm" variant="outline" className="text-muted-foreground" onClick={() => handleStatusChange(f.id, "false_positive")}>
                                          False Positive
                                        </Button>
                                      </div>
                                    </div>
                                  </TableCell>
                                </TableRow>
                              )}
                            </React.Fragment>
                          );
                        })}
                      </TableBody>
                    </Table>
                  </CardContent>
                )}
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
