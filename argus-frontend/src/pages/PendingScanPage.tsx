import { Clock, Play, Trash2, ArrowUpDown } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

const MOCK_PENDING = [
  {
    id: "q-001",
    target: "MCP Server Alpha",
    mode: "Full Scan",
    scheduled: "Today 22:00 UTC",
    priority: "high",
    agents: 12,
  },
  {
    id: "q-002",
    target: "AI Agent Bravo",
    mode: "Phase 5 Only",
    scheduled: "Tomorrow 02:00 UTC",
    priority: "normal",
    agents: 2,
  },
  {
    id: "q-003",
    target: "Pipeline Charlie",
    mode: "Quick Scan",
    scheduled: "Tomorrow 04:00 UTC",
    priority: "normal",
    agents: 5,
  },
];

export function PendingScanPage() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Pending Scans</h2>
          <p className="text-sm text-muted-foreground">
            Queued and scheduled scans waiting to execute
          </p>
        </div>
        <Badge variant="secondary">{MOCK_PENDING.length} in queue</Badge>
      </div>

      {MOCK_PENDING.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Clock className="h-12 w-12 text-muted-foreground/30" />
            <p className="mt-4 text-sm text-muted-foreground">No pending scans</p>
            <p className="text-xs text-muted-foreground/60">
              Schedule a scan or launch one from the Live Scan page
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {MOCK_PENDING.map((scan) => (
            <Card key={scan.id}>
              <CardContent className="flex items-center gap-4 p-4">
                <div className="flex h-10 w-10 items-center justify-center rounded-md bg-primary/10">
                  <Clock className="h-5 w-5 text-primary" />
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <p className="font-medium">{scan.target}</p>
                    <Badge variant="outline" className="text-xs">
                      {scan.mode}
                    </Badge>
                    {scan.priority === "high" && (
                      <Badge className="bg-orange-600 text-xs">High Priority</Badge>
                    )}
                  </div>
                  <p className="text-sm text-muted-foreground">
                    Scheduled: {scan.scheduled} • {scan.agents} agents
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <Button variant="outline" size="sm" className="gap-1">
                    <ArrowUpDown className="h-3 w-3" />
                    Reorder
                  </Button>
                  <Button size="sm" className="gap-1">
                    <Play className="h-3 w-3" />
                    Run Now
                  </Button>
                  <Button variant="ghost" size="sm" className="text-red-400 hover:text-red-300">
                    <Trash2 className="h-3 w-3" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Scheduled recurring scans */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium text-muted-foreground">
            Recurring Schedules
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {[
              { target: "MCP Server Alpha", freq: "Every 24h", nextRun: "Tomorrow 02:00 UTC", enabled: true },
              { target: "AI Agent Bravo", freq: "Every 7d", nextRun: "Mon 04:00 UTC", enabled: true },
              { target: "Pipeline Charlie", freq: "Every 24h", nextRun: "Tomorrow 02:00 UTC", enabled: false },
            ].map((sched) => (
              <div
                key={sched.target}
                className="flex items-center justify-between rounded-md border border-border p-3"
              >
                <div>
                  <p className="text-sm font-medium">{sched.target}</p>
                  <p className="text-xs text-muted-foreground">
                    {sched.freq} • Next: {sched.nextRun}
                  </p>
                </div>
                <Badge variant={sched.enabled ? "default" : "secondary"}>
                  {sched.enabled ? "Active" : "Paused"}
                </Badge>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
