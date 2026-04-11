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
} from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
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
import { getFindings, updateFindingStatus } from "@/api/client";

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
  lastSeen: string;
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

export function FindingsPage() {
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
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
        const data = await getFindings(params.toString() || undefined);
        if (cancelled) return;
        setFindings(
          (data.findings || []).map((f: Record<string, unknown>) => ({
            id: String(f.id ?? ""),
            title: String(f.title ?? ""),
            severity: String(f.severity ?? "medium"),
            agent: String(f.agent_type ?? ""),
            target: String(f.target_surface ?? f.target ?? ""),
            owasp: String(f.owasp_agentic ?? f.owasp_category ?? ""),
            verdictWeight: Number(typeof f.verdict_score === "object" && f.verdict_score !== null ? (f.verdict_score as Record<string, unknown>).weight ?? 0 : f.verdict_score ?? f.verdict_weight ?? f.confidence ?? 0),
            status: String(f.triage_status ?? f.status ?? "open"),
            firstSeen: String(f.created_at ?? ""),
            lastSeen: String(f.updated_at ?? f.created_at ?? ""),
          }))
        );
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
      setFindings((prev) =>
        prev.map((f) => (f.id === findingId ? { ...f, status: newStatus } : f))
      );
    } catch {
      // silently ignore — could show toast
    }
  };

  if (loading && findings.length === 0) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  if (error && findings.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-center">
        <AlertTriangle className="h-8 w-8 text-red-500" />
        <p className="mt-2 text-sm text-muted-foreground">{error}</p>
        <Button variant="outline" size="sm" className="mt-4" onClick={() => window.location.reload()}>Retry</Button>
      </div>
    );
  }

  const filtered = findings;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">All Findings</h2>
          <p className="text-sm text-muted-foreground">
            {findings.length} findings across all targets — triage, filter, export
          </p>
        </div>
        <Button variant="outline" size="sm" className="gap-1">
          <Download className="h-3 w-3" />
          Export
        </Button>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <Input
          placeholder="Search findings..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="max-w-xs"
        />
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

      {/* Findings table */}
      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-8"></TableHead>
                <TableHead>ID</TableHead>
                <TableHead>Finding</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Agent</TableHead>
                <TableHead>Target</TableHead>
                <TableHead>Confidence</TableHead>
                <TableHead>Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((f) => {
                const StatusIcon = STATUS_ICONS[f.status] || AlertTriangle;
                return (
                  <React.Fragment key={f.id}>
                    <TableRow
                      className="cursor-pointer"
                      onClick={() => setExpanded(expanded === f.id ? null : f.id)}
                    >
                      <TableCell>
                        {expanded === f.id ? (
                          <ChevronDown className="h-3 w-3" />
                        ) : (
                          <ChevronRight className="h-3 w-3" />
                        )}
                      </TableCell>
                      <TableCell className="font-mono text-xs">{f.id}</TableCell>
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
                    {expanded === f.id && (
                      <TableRow key={`${f.id}-detail`}>
                        <TableCell colSpan={8}>
                          <div className="space-y-3 rounded-md bg-background p-4">
                            <div className="grid grid-cols-2 gap-4 text-sm">
                              <div>
                                <p className="text-xs text-muted-foreground">OWASP Mapping</p>
                                <p className="font-medium">{f.owasp}</p>
                              </div>
                              <div>
                                <p className="text-xs text-muted-foreground">VERDICT WEIGHT</p>
                                <p className="font-medium">{f.verdictWeight}</p>
                              </div>
                              <div>
                                <p className="text-xs text-muted-foreground">First Seen</p>
                                <p>{f.firstSeen}</p>
                              </div>
                              <div>
                                <p className="text-xs text-muted-foreground">Last Seen</p>
                                <p>{f.lastSeen}</p>
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
      </Card>
    </div>
  );
}
