import { useState, useEffect } from "react";
import {
  CheckCircle,
  Download,
  Eye,
  Filter,
  ArrowUpDown,
  Calendar,
  Loader2,
  AlertTriangle,
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
import { getScans } from "@/api/client";

interface CompletedScan {
  id: string;
  target: string;
  date: string;
  duration: string;
  agents: number;
  findings: { critical: number; high: number; medium: number; low: number };
  status: string;
}

export function CompletedScanPage() {
  const [search, setSearch] = useState("");
  const [scans, setScans] = useState<CompletedScan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

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
            findings: {
              critical: Number((s.findings as Record<string, unknown>)?.critical ?? s.critical ?? 0),
              high: Number((s.findings as Record<string, unknown>)?.high ?? s.high ?? 0),
              medium: Number((s.findings as Record<string, unknown>)?.medium ?? s.medium ?? 0),
              low: Number((s.findings as Record<string, unknown>)?.low ?? s.low ?? 0),
            },
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
  }, [search]);

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
            Scan history with comparison and export
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

      {/* Scan table */}
      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
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
                const total =
                  scan.findings.critical +
                  scan.findings.high +
                  scan.findings.medium +
                  scan.findings.low;
                return (
                  <TableRow key={scan.id}>
                    <TableCell className="font-mono text-xs">{scan.id}</TableCell>
                    <TableCell className="font-medium">{scan.target}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {scan.date}
                    </TableCell>
                    <TableCell className="text-sm">{scan.duration}</TableCell>
                    <TableCell>{scan.agents}</TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1">
                        {scan.findings.critical > 0 && (
                          <Badge className="bg-red-600 text-xs">{scan.findings.critical}C</Badge>
                        )}
                        {scan.findings.high > 0 && (
                          <Badge className="bg-orange-600 text-xs">{scan.findings.high}H</Badge>
                        )}
                        <span className="text-xs text-muted-foreground">{total} total</span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="gap-1 text-green-400">
                        <CheckCircle className="h-3 w-3" />
                        Done
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        <Button variant="ghost" size="sm">
                          <Eye className="h-3 w-3" />
                        </Button>
                        <Button variant="ghost" size="sm">
                          <Download className="h-3 w-3" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
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
