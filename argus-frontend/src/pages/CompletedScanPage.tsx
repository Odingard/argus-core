import { useState } from "react";
import {
  CheckCircle,
  Download,
  Eye,
  Filter,
  ArrowUpDown,
  Calendar,
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

const MOCK_SCANS = [
  {
    id: "scan-a1b2c3",
    target: "MCP Server Alpha",
    date: "2026-04-10 14:30 UTC",
    duration: "4m 23s",
    agents: 12,
    findings: { critical: 1, high: 3, medium: 5, low: 2 },
    status: "completed",
  },
  {
    id: "scan-d4e5f6",
    target: "AI Agent Bravo",
    date: "2026-04-09 02:00 UTC",
    duration: "3m 11s",
    agents: 12,
    findings: { critical: 0, high: 2, medium: 4, low: 1 },
    status: "completed",
  },
  {
    id: "scan-g7h8i9",
    target: "MCP Server Alpha",
    date: "2026-04-08 02:00 UTC",
    duration: "4m 45s",
    agents: 12,
    findings: { critical: 2, high: 4, medium: 6, low: 3 },
    status: "completed",
  },
  {
    id: "scan-j0k1l2",
    target: "Pipeline Charlie",
    date: "2026-04-07 22:00 UTC",
    duration: "2m 58s",
    agents: 5,
    findings: { critical: 0, high: 1, medium: 3, low: 0 },
    status: "completed",
  },
  {
    id: "scan-m3n4o5",
    target: "Memory Store Delta",
    date: "2026-04-06 02:00 UTC",
    duration: "5m 12s",
    agents: 12,
    findings: { critical: 3, high: 5, medium: 8, low: 4 },
    status: "completed",
  },
];

export function CompletedScanPage() {
  const [search, setSearch] = useState("");

  const filtered = MOCK_SCANS.filter(
    (s) =>
      s.target.toLowerCase().includes(search.toLowerCase()) ||
      s.id.toLowerCase().includes(search.toLowerCase())
  );

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
