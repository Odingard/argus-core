import React, { useState } from "react";
import {
  AlertTriangle,
  Download,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  CheckCircle,
  Clock,
  XCircle,
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

interface Finding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  agent: string;
  target: string;
  owasp: string;
  verdictWeight: number;
  status: "open" | "triaged" | "resolved" | "false_positive";
  firstSeen: string;
  lastSeen: string;
}

const MOCK_FINDINGS: Finding[] = [
  {
    id: "F-001",
    title: "Persona drift detected — authority inflation after 5 turns",
    severity: "critical",
    agent: "PH-11",
    target: "Code Review Agent",
    owasp: "AA11 — Persona Hijacking",
    verdictWeight: 0.92,
    status: "open",
    firstSeen: "2026-04-10",
    lastSeen: "2026-04-10",
  },
  {
    id: "F-002",
    title: "Memory boundary collapse — context bleed between sessions",
    severity: "critical",
    agent: "MB-12",
    target: "Conversation History",
    owasp: "AA12 — Memory Boundary Collapse",
    verdictWeight: 0.88,
    status: "open",
    firstSeen: "2026-04-09",
    lastSeen: "2026-04-10",
  },
  {
    id: "F-003",
    title: "Hidden instruction in tool description follows",
    severity: "high",
    agent: "TP-02",
    target: "Primary MCP Server",
    owasp: "AA06 — Tool Misuse",
    verdictWeight: 0.85,
    status: "triaged",
    firstSeen: "2026-04-08",
    lastSeen: "2026-04-10",
  },
  {
    id: "F-004",
    title: "System prompt extractable via role-play technique",
    severity: "high",
    agent: "ME-10",
    target: "Customer Support Agent",
    owasp: "AA08 — Model Theft",
    verdictWeight: 0.79,
    status: "open",
    firstSeen: "2026-04-07",
    lastSeen: "2026-04-10",
  },
  {
    id: "F-005",
    title: "Cross-agent data exfiltration via shared memory",
    severity: "high",
    agent: "CX-06",
    target: "Customer Intake Pipeline",
    owasp: "AA04 — Excessive Agency",
    verdictWeight: 0.76,
    status: "open",
    firstSeen: "2026-04-06",
    lastSeen: "2026-04-09",
  },
  {
    id: "F-006",
    title: "Privilege escalation via confused deputy chain",
    severity: "medium",
    agent: "PE-07",
    target: "Code Review Pipeline",
    owasp: "AA04 — Excessive Agency",
    verdictWeight: 0.71,
    status: "triaged",
    firstSeen: "2026-04-05",
    lastSeen: "2026-04-08",
  },
  {
    id: "F-007",
    title: "Canary token leaked from context store to conversation",
    severity: "medium",
    agent: "MP-03",
    target: "Customer Context Store",
    owasp: "AA05 — Improper Output",
    verdictWeight: 0.65,
    status: "resolved",
    firstSeen: "2026-04-03",
    lastSeen: "2026-04-03",
  },
  {
    id: "F-008",
    title: "Identity header spoofing accepted without verification",
    severity: "medium",
    agent: "IS-04",
    target: "Primary MCP Server",
    owasp: "AA02 — Sensitive Data",
    verdictWeight: 0.62,
    status: "open",
    firstSeen: "2026-04-02",
    lastSeen: "2026-04-10",
  },
];

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-red-600",
  high: "bg-orange-600",
  medium: "bg-yellow-600",
  low: "bg-blue-600",
  info: "bg-gray-600",
};

const STATUS_ICONS: Record<string, React.ElementType> = {
  open: AlertTriangle,
  triaged: Clock,
  resolved: CheckCircle,
  false_positive: XCircle,
};

export function FindingsPage() {
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [expanded, setExpanded] = useState<string | null>(null);

  const filtered = MOCK_FINDINGS.filter((f) => {
    if (severityFilter !== "all" && f.severity !== severityFilter) return false;
    if (statusFilter !== "all" && f.status !== statusFilter) return false;
    if (search && !f.title.toLowerCase().includes(search.toLowerCase()) && !f.id.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">All Findings</h2>
          <p className="text-sm text-muted-foreground">
            {MOCK_FINDINGS.length} findings across all targets — triage, filter, export
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
                              <Button size="sm" variant="outline">Mark Triaged</Button>
                              <Button size="sm" variant="outline">Mark Resolved</Button>
                              <Button size="sm" variant="outline" className="text-muted-foreground">
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
