import {
  Database,
  Plus,
  Shield,
  AlertTriangle,
  CheckCircle,
  Key,
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

const MOCK_STORES = [
  {
    id: "mem-001",
    name: "Customer Context Store",
    type: "Vector DB (Pinecone)",
    endpoint: "https://pinecone.example.com",
    status: "healthy",
    boundaryIntegrity: 94,
    canaryTokens: { planted: 5, leaked: 0 },
    lastScan: "4 hours ago",
    findings: { critical: 0, high: 0, medium: 1, low: 2 },
  },
  {
    id: "mem-002",
    name: "Conversation History",
    type: "Redis + LangChain Memory",
    endpoint: "redis://memory.example.com:6379",
    status: "boundary_leak",
    boundaryIntegrity: 41,
    canaryTokens: { planted: 8, leaked: 3 },
    lastScan: "1 hour ago",
    findings: { critical: 2, high: 3, medium: 1, low: 0 },
  },
  {
    id: "mem-003",
    name: "RAG Knowledge Base",
    type: "ChromaDB",
    endpoint: "http://chroma.internal:8000",
    status: "healthy",
    boundaryIntegrity: 88,
    canaryTokens: { planted: 4, leaked: 0 },
    lastScan: "12 hours ago",
    findings: { critical: 0, high: 1, medium: 2, low: 1 },
  },
];

export function MemoryStoresPage() {
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
                <Input placeholder="Customer Context Store" className="mt-1" />
              </div>
              <div>
                <Label>Type</Label>
                <Input placeholder="Vector DB, Redis, ChromaDB..." className="mt-1" />
              </div>
              <div>
                <Label>Endpoint</Label>
                <Input placeholder="https://pinecone.example.com" className="mt-1" />
              </div>
              <Button className="w-full">Add Store</Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {MOCK_STORES.map((store) => (
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
