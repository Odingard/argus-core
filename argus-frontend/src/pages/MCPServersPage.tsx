import { useState, useEffect } from "react";
import {
  Server,
  Plus,
  MoreVertical,
  CheckCircle,
  AlertTriangle,
  XCircle,
  RefreshCw,
  Shield,
  Wrench,
  Loader2,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { getTargets, createTarget, deleteTarget } from "@/api/client";

interface MCPServer {
  id: string;
  name: string;
  url: string;
  status: string;
  tools: number;
  lastScan: string;
  findings: { critical: number; high: number; medium: number; low: number };
  riskScore: number;
}

export function MCPServersPage() {
  const [servers, setServers] = useState<MCPServer[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [newName, setNewName] = useState("");
  const [newUrl, setNewUrl] = useState("");

  useEffect(() => {
    loadServers();
  }, []);

  async function loadServers() {
    try {
      setLoading(true);
      const data = await getTargets();
      const mcpTargets = (data.targets || []).filter(
        (t: Record<string, unknown>) => String(t.target_type ?? t.type ?? "").toLowerCase().includes("mcp")
      );
      setServers(
        mcpTargets.map((t: Record<string, unknown>) => ({
          id: String(t.id ?? ""),
          name: String(t.name ?? ""),
          url: String(t.url ?? t.endpoint ?? ""),
          status: String(t.status ?? "healthy"),
          tools: Number(t.tools ?? 0),
          lastScan: String(t.last_scan ?? "Never"),
          findings: { critical: 0, high: 0, medium: 0, low: 0 },
          riskScore: Number(t.risk_score ?? 0),
        }))
      );
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load");
    } finally {
      setLoading(false);
    }
  }

  async function handleAddServer() {
    if (!newName || !newUrl) return;
    try {
      await createTarget({ name: newName, url: newUrl, type: "mcp_server" });
      setNewName("");
      setNewUrl("");
      loadServers();
    } catch {
      // ignore
    }
  }

  async function handleDelete(id: string) {
    try {
      await deleteTarget(id);
      loadServers();
    } catch {
      // ignore
    }
  }

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
        <Button variant="outline" size="sm" className="mt-4" onClick={() => loadServers()}>Retry</Button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">MCP Servers</h2>
          <p className="text-sm text-muted-foreground">
            Manage MCP server targets — tool inventory, health, risk profile
          </p>
        </div>
        <Dialog>
          <DialogTrigger asChild>
            <Button className="gap-2">
              <Plus className="h-4 w-4" />
              Add Server
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Add MCP Server</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 pt-4">
              <div>
                <Label>Server Name</Label>
                <Input placeholder="Production MCP Server" className="mt-1" value={newName} onChange={(e) => setNewName(e.target.value)} />
              </div>
              <div>
                <Label>Server URL</Label>
                <Input placeholder="https://mcp.example.com:8443" className="mt-1" value={newUrl} onChange={(e) => setNewUrl(e.target.value)} />
              </div>
              <div>
                <Label>Auth Token (optional)</Label>
                <Input type="password" placeholder="Bearer token" className="mt-1" />
              </div>
              <Button className="w-full" onClick={handleAddServer}>Add Server</Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      {/* Server cards */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {servers.map((server) => (
          <Card key={server.id}>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-md bg-primary/10">
                    <Server className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <CardTitle className="text-base">{server.name}</CardTitle>
                    <p className="text-xs font-mono text-muted-foreground">{server.url}</p>
                  </div>
                </div>
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="ghost" size="sm">
                      <MoreVertical className="h-4 w-4" />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    <DropdownMenuItem>Edit</DropdownMenuItem>
                    <DropdownMenuItem>Scan Now</DropdownMenuItem>
                    <DropdownMenuItem>View History</DropdownMenuItem>
                    <DropdownMenuItem className="text-red-400">Remove</DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Status + health */}
              <div className="flex items-center justify-between">
                <StatusBadge status={server.status} />
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <RefreshCw className="h-3 w-3" />
                  Last scan: {server.lastScan}
                </div>
              </div>

              {/* Tool inventory + Risk */}
              <div className="grid grid-cols-2 gap-4">
                <div className="rounded-md border border-border p-3">
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <Wrench className="h-3 w-3" />
                    Tool Inventory
                  </div>
                  <p className="mt-1 text-lg font-bold">{server.tools}</p>
                </div>
                <div className="rounded-md border border-border p-3">
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <Shield className="h-3 w-3" />
                    Risk Score
                  </div>
                  <p className={`mt-1 text-lg font-bold ${server.riskScore > 70 ? "text-red-500" : server.riskScore > 40 ? "text-yellow-500" : "text-green-500"}`}>
                    {server.riskScore}/100
                  </p>
                </div>
              </div>

              {/* Risk bar */}
              <div>
                <Progress
                  value={server.riskScore}
                  className={`h-1.5 ${server.riskScore > 70 ? "[&>div]:bg-red-500" : server.riskScore > 40 ? "[&>div]:bg-yellow-500" : "[&>div]:bg-green-500"}`}
                />
              </div>

              {/* Findings summary */}
              <div className="flex items-center gap-2">
                <span className="text-xs text-muted-foreground">Findings:</span>
                {server.findings.critical > 0 && (
                  <Badge className="bg-red-600 text-xs">{server.findings.critical} Critical</Badge>
                )}
                {server.findings.high > 0 && (
                  <Badge className="bg-orange-600 text-xs">{server.findings.high} High</Badge>
                )}
                {server.findings.medium > 0 && (
                  <Badge className="bg-yellow-600 text-xs">{server.findings.medium} Medium</Badge>
                )}
                {server.findings.low > 0 && (
                  <Badge variant="secondary" className="text-xs">{server.findings.low} Low</Badge>
                )}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const config: Record<string, { icon: React.ElementType; label: string; className: string }> = {
    healthy: { icon: CheckCircle, label: "Healthy", className: "text-green-400 border-green-400/50" },
    degraded: { icon: AlertTriangle, label: "Degraded", className: "text-yellow-400 border-yellow-400/50" },
    offline: { icon: XCircle, label: "Offline", className: "text-red-400 border-red-400/50" },
  };
  const c = config[status] || config.offline;
  const Icon = c.icon;
  return (
    <Badge variant="outline" className={`gap-1 ${c.className}`}>
      <Icon className="h-3 w-3" />
      {c.label}
    </Badge>
  );
}
