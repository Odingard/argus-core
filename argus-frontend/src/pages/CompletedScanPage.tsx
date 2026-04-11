import React, { useState, useEffect } from "react";
import {
  CheckCircle,
  Download,
  Eye,
  Filter,
  ArrowUpDown,
  Calendar,
  Loader2,
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  XCircle,
  Clock,
  ExternalLink,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { getScans, getScanFindings } from "@/api/client";

interface CompletedScan {
  id: string;
  target: string;
  date: string;
  duration: string;
  agents: number;
  totalFindings: number;
  status: string;
}

interface ScanFinding {
  id: string;
  title: string;
  severity: string;
  agent: string;
  target: string;
  status: string;
  confidence: number;
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

export function CompletedScanPage() {
  const [search, setSearch] = useState("");
  const [scans, setScans] = useState<CompletedScan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedScan, setExpandedScan] = useState<string | null>(null);
  const [scanFindings, setScanFindings] = useState<Record<string, ScanFinding[]>>({});
  const [loadingFindings, setLoadingFindings] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        setLoading(true);
        const params = new URLSearchParams();
        params.set("status", "completed");
        if (search) params.set("search", search);
        const data = await getScans(params.toString());
        if (cancelled) return;
        setScans(
          (data.scans || []).map((s: Record<string, unknown>) => ({
            id: String(s.id ?? ""),
            target: String(s.target ?? s.target_name ?? ""),
            date: String(s.created_at ?? s.date ?? ""),
            duration: s.duration_seconds ? `${Math.floor(Number(s.duration_seconds) / 60)}m ${Math.round(Number(s.duration_seconds) % 60)}s` : String(s.duration ?? "N/A"),
            agents: Number(s.agents_deployed ?? s.agents ?? s.agent_count ?? 0),
            totalFindings: Number(s.total_findings ?? 0),
            status: String(s.status ?? "completed"),
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

  const handleExpandScan = async (scanId: string) => {
    if (expandedScan === scanId) {
      setExpandedScan(null);
      return;
    }
    setExpandedScan(scanId);
    if (scanFindings[scanId]) return; // already loaded
    try {
      setLoadingFindings(scanId);
      const data = await getScanFindings(scanId);
      const findings: ScanFinding[] = (data.findings || []).map((f: Record<string, unknown>) => ({
        id: String(f.id ?? ""),
        title: String(f.title ?? ""),
        severity: String(f.severity ?? "medium"),
        agent: String(f.agent_type ?? ""),
        target: String(f.target_surface ?? f.target ?? ""),
        status: String(f.status ?? "unvalidated"),
        confidence: Number(
          typeof f.verdict_score === "object" && f.verdict_score !== null
            ? (f.verdict_score as Record<string, unknown>).weight ?? 0
            : f.verdict_score ?? 0
        ),
      }));
      setScanFindings((prev) => ({ ...prev, [scanId]: findings }));
    } catch {
      setScanFindings((prev) => ({ ...prev, [scanId]: [] }));
    } finally {
      setLoadingFindings(null);
    }
  };

  if (loading && scans.length === 0) {
    return (<div className="flex items-center justify-center py-20"><Loader2 className="h-8 w-8 animate-spin text-primary" /></div>);
  }
  if (error && scans.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-center">
        <AlertTriangle className="h-8 w-8 text-red-500" />
        <p className="mt-2 text-sm text-muted-foreground">{error}</p>
        <Button variant="outline" size="sm" className="mt-4" onClick={() => window.location.reload()}>Retry</Button>
      </div>
    );
  }

  const filtered = search
    ? scans.filter(
        (s) =>
          s.target.toLowerCase().includes(search.toLowerCase()) ||
          s.id.toLowerCase().includes(search.toLowerCase())
      )
    : scans;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Completed Scans</h2>
          <p className="text-sm text-muted-foreground">
            Scan history — click a scan to view its findings
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" className="gap-1">
            <Download className="h-3 w-3" />
            Export All
          </Button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <Input
          placeholder="Search by target or scan ID..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="max-w-sm"
        />
        <Button variant="outline" size="sm" className="gap-1">
          <Filter className="h-3 w-3" />
          Filters
        </Button>
        <Button variant="outline" size="sm" className="gap-1">
          <Calendar className="h-3 w-3" />
          Date Range
        </Button>
        <Button variant="outline" size="sm" className="gap-1">
          <ArrowUpDown className="h-3 w-3" />
          Sort
        </Button>
      </div>

      {/* Scan table with expandable findings */}
      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-8"></TableHead>
                <TableHead>Scan ID</TableHead>
                <TableHead>Target</TableHead>
                <TableHead>Date</TableHead>
                <TableHead>Duration</TableHead>
                <TableHead>Agents</TableHead>
                <TableHead>Findings</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((scan) => {
                const isExpanded = expandedScan === scan.id;
                const findings = scanFindings[scan.id] || [];
                const isLoadingThis = loadingFindings === scan.id;
                return (
                  <React.Fragment key={scan.id}>
                    <TableRow className="cursor-pointer" onClick={() => handleExpandScan(scan.id)}>
                      <TableCell>
                        {isExpanded ? (
                          <ChevronDown className="h-3 w-3" />
                        ) : (
                          <ChevronRight className="h-3 w-3" />
                        )}
                      </TableCell>
                      <TableCell className="font-mono text-xs">{scan.id.slice(0, 8)}...</TableCell>
                      <TableCell className="font-medium">{scan.target}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {scan.date ? new Date(scan.date).toLocaleString() : scan.date}
                      </TableCell>
                      <TableCell className="text-sm">{scan.duration}</TableCell>
                      <TableCell>{scan.agents}</TableCell>
                      <TableCell>
                        <span className="text-sm font-medium">{scan.totalFindings} findings</span>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="gap-1 text-green-400">
                          <CheckCircle className="h-3 w-3" />
                          Done
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-1">
                          <Button variant="ghost" size="sm" onClick={(e) => { e.stopPropagation(); handleExpandScan(scan.id); }}>
                            <Eye className="h-3 w-3" />
                          </Button>
                          <Button variant="ghost" size="sm">
                            <Download className="h-3 w-3" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                    {isExpanded && (
                      <TableRow>
                        <TableCell colSpan={9} className="bg-muted/30 p-4">
                          {isLoadingThis ? (
                            <div className="flex items-center justify-center py-4">
                              <Loader2 className="h-5 w-5 animate-spin text-primary" />
                              <span className="ml-2 text-sm text-muted-foreground">Loading findings for scan {scan.id.slice(0, 8)}...</span>
                            </div>
                          ) : findings.length === 0 ? (
                            <p className="py-4 text-center text-sm text-muted-foreground">No findings for this scan</p>
                          ) : (
                            <div className="space-y-2">
                              <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                                Findings for Scan {scan.id.slice(0, 8)}... ({findings.length} total)
                              </p>
                              <Table>
                                <TableHeader>
                                  <TableRow>
                                    <TableHead>Finding</TableHead>
                                    <TableHead>Severity</TableHead>
                                    <TableHead>Agent</TableHead>
                                    <TableHead>Target Surface</TableHead>
                                    <TableHead>Confidence</TableHead>
                                    <TableHead>Status</TableHead>
                                    <TableHead></TableHead>
                                  </TableRow>
                                </TableHeader>
                                <TableBody>
                                  {findings.map((f) => {
                                    const StatusIcon = STATUS_ICONS[f.status] || AlertTriangle;
                                    return (
                                      <TableRow key={f.id}>
                                        <TableCell className="max-w-xs truncate text-sm font-medium">{f.title}</TableCell>
                                        <TableCell>
                                          <Badge className={`text-xs ${SEVERITY_STYLES[f.severity]}`}>{f.severity}</Badge>
                                        </TableCell>
                                        <TableCell className="font-mono text-xs">{f.agent}</TableCell>
                                        <TableCell className="text-sm">{f.target}</TableCell>
                                        <TableCell>
                                          <span className="text-sm font-medium">{(f.confidence * 100).toFixed(0)}%</span>
                                        </TableCell>
                                        <TableCell>
                                          <Badge variant="outline" className="gap-1 text-xs capitalize">
                                            <StatusIcon className="h-3 w-3" />
                                            {f.status.replace("_", " ")}
                                          </Badge>
                                        </TableCell>
                                        <TableCell>
                                          <Button variant="ghost" size="sm" className="gap-1">
                                            <ExternalLink className="h-3 w-3" />
                                          </Button>
                                        </TableCell>
                                      </TableRow>
                                    );
                                  })}
                                </TableBody>
                              </Table>
                            </div>
                          )}
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

      {/* Comparison prompt */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium text-muted-foreground">
            Scan Comparison
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            Select two scans of the same target to compare findings, track regression, and
            measure remediation progress.
          </p>
          <Button variant="outline" size="sm" className="mt-3">
            Compare Scans
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
