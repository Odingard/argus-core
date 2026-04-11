import { useState, useEffect } from "react";
import {
  Database,
  Plus,
  Shield,
  AlertTriangle,
  CheckCircle,
  Key,
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
import { getTargets, createTarget } from "@/api/client";

interface MemoryStore {
  id: string;
  name: string;
  type: string;
  endpoint: string;
  status: string;
  boundaryIntegrity: number;
  canaryTokens: { planted: number; leaked: number };
  lastScan: string;
  findings: { critical: number; high: number; medium: number; low: number };
}

export function MemoryStoresPage() {
  const [stores, setStores] = useState<MemoryStore[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [newName, setNewName] = useState("");
  const [newType, setNewType] = useState("");
  const [newEndpoint, setNewEndpoint] = useState("");

  useEffect(() => { loadStores(); }, []);

  async function loadStores() {
    try {
      setLoading(true);
      const data = await getTargets();
      const memTargets = (data.targets || []).filter(
        (t: Record<string, unknown>) => String(t.type ?? "").toLowerCase().includes("memory")
      );
      setStores(
        memTargets.map((t: Record<string, unknown>) => ({
          id: String(t.id ?? ""),
          name: String(t.name ?? ""),
          type: String(t.store_type ?? t.type ?? ""),
          endpoint: String(t.url ?? t.endpoint ?? ""),
          status: String(t.status ?? "healthy"),
          boundaryIntegrity: Number(t.boundary_integrity ?? 100),
          canaryTokens: { planted: Number((t.canary_tokens as Record<string, unknown>)?.planted ?? 0), leaked: Number((t.canary_tokens as Record<string, unknown>)?.leaked ?? 0) },
          lastScan: String(t.last_scan ?? "Never"),
          findings: { critical: 0, high: 0, medium: 0, low: 0 },
        }))
      );
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load");
    } finally {
      setLoading(false);
    }
  }

  async function handleAdd() {
    if (!newName) return;
    try {
      await createTarget({ name: newName, type: "memory_store", store_type: newType, url: newEndpoint });
      setNewName(""); setNewType(""); setNewEndpoint("");
      loadStores();
    } catch { /* ignore */ }
  }

  if (loading) {
    return (<div className="flex items-center justify-center py-20"><Loader2 className="h-8 w-8 animate-spin text-primary" /></div>);
  }
  if (error) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-center">
        <AlertTriangle className="h-8 w-8 text-red-500" />
        <p className="mt-2 text-sm text-muted-foreground">{error}</p>
        <Button variant="outline" size="sm" className="mt-4" onClick={() => loadStores()}>Retry</Button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Memory Stores</h2>
          <p className="text-sm text-muted-foreground">
            Memory targets — boundary mapping, canary token status, integrity monitoring
          </p>
        </div>
        <Dialog>
          <DialogTrigger asChild>
            <Button className="gap-2">
              <Plus className="h-4 w-4" />
              Add Store
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Add Memory Store</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 pt-4">
              <div>
                <Label>Store Name</Label>
                <Input placeholder="Customer Context Store" className="mt-1" value={newName} onChange={(e) => setNewName(e.target.value)} />
              </div>
              <div>
                <Label>Type</Label>
                <Input placeholder="Vector DB, Redis, ChromaDB..." className="mt-1" value={newType} onChange={(e) => setNewType(e.target.value)} />
              </div>
              <div>
                <Label>Endpoint</Label>
                <Input placeholder="https://pinecone.example.com" className="mt-1" value={newEndpoint} onChange={(e) => setNewEndpoint(e.target.value)} />
              </div>
              <Button className="w-full" onClick={handleAdd}>Add Store</Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {stores.map((store) => (
          <Card key={store.id}>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-md bg-primary/10">
                    <Database className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <CardTitle className="text-base">{store.name}</CardTitle>
                    <p className="text-xs text-muted-foreground">{store.type}</p>
                  </div>
                </div>
                {store.status === "boundary_leak" ? (
                  <Badge className="gap-1 bg-red-600">
                    <AlertTriangle className="h-3 w-3" />
                    Boundary Leak
                  </Badge>
                ) : (
                  <Badge variant="outline" className="gap-1 text-green-400 border-green-400/50">
                    <CheckCircle className="h-3 w-3" />
                    Healthy
                  </Badge>
                )}
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="rounded-md border border-border p-3">
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <Shield className="h-3 w-3" />
                    Boundary Integrity
                  </div>
                  <p className={`mt-1 text-lg font-bold ${store.boundaryIntegrity < 50 ? "text-red-500" : store.boundaryIntegrity < 75 ? "text-yellow-500" : "text-green-500"}`}>
                    {store.boundaryIntegrity}%
                  </p>
                  <Progress
                    value={store.boundaryIntegrity}
                    className={`mt-1 h-1 ${store.boundaryIntegrity < 50 ? "[&>div]:bg-red-500" : store.boundaryIntegrity < 75 ? "[&>div]:bg-yellow-500" : "[&>div]:bg-green-500"}`}
                  />
                </div>
                <div className="rounded-md border border-border p-3">
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <Key className="h-3 w-3" />
                    Canary Tokens
                  </div>
                  <p className="mt-1 text-sm">
                    <span className="font-bold">{store.canaryTokens.planted}</span> planted
                    {store.canaryTokens.leaked > 0 && (
                      <span className="ml-2 text-red-500 font-bold">
                        {store.canaryTokens.leaked} leaked!
                      </span>
                    )}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <span className="text-xs text-muted-foreground">Findings:</span>
                {store.findings.critical > 0 && <Badge className="bg-red-600 text-xs">{store.findings.critical}C</Badge>}
                {store.findings.high > 0 && <Badge className="bg-orange-600 text-xs">{store.findings.high}H</Badge>}
                {store.findings.medium > 0 && <Badge className="bg-yellow-600 text-xs">{store.findings.medium}M</Badge>}
                {store.findings.low > 0 && <Badge variant="secondary" className="text-xs">{store.findings.low}L</Badge>}
              </div>

              <p className="text-xs text-muted-foreground">Last scan: {store.lastScan}</p>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
