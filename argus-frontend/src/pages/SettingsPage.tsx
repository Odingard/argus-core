import { useState, useEffect } from "react";
import {
  Key,
  Sliders,
  Bell,
  Users,
  Plug,
  Brain,
  FileDown,
  Save,
  Loader2,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { getSettings, saveSettings } from "@/api/client";

type SettingsTab = "api" | "scan" | "llm" | "integrations" | "notifications" | "users" | "cerberus";

const TABS: { key: SettingsTab; label: string; icon: React.ElementType }[] = [
  { key: "api", label: "API Keys", icon: Key },
  { key: "scan", label: "Scan Profiles", icon: Sliders },
  { key: "llm", label: "LLM Config", icon: Brain },
  { key: "integrations", label: "Integrations", icon: Plug },
  { key: "notifications", label: "Notifications", icon: Bell },
  { key: "users", label: "Users", icon: Users },
  { key: "cerberus", label: "CERBERUS Export", icon: FileDown },
];

export function SettingsPage() {
  const [tab, setTab] = useState<SettingsTab>("api");
  const [settings, setSettings] = useState<Record<string, unknown>>({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        setLoading(true);
        const data = await getSettings();
        if (!cancelled) setSettings(data.settings || {});
      } catch {
        // Settings endpoint may not exist yet — use defaults
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => { cancelled = true; };
  }, []);

  if (loading) {
    return (<div className="flex items-center justify-center py-20"><Loader2 className="h-8 w-8 animate-spin text-primary" /></div>);
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Settings</h2>
        <p className="text-sm text-muted-foreground">
          Platform configuration — API keys, scan profiles, LLM backend, integrations
        </p>
      </div>

      <div className="flex gap-6">
        {/* Tab sidebar */}
        <div className="w-48 shrink-0 space-y-1">
          {TABS.map((t) => {
            const Icon = t.icon;
            return (
              <button
                key={t.key}
                onClick={() => setTab(t.key)}
                className={`flex w-full items-center gap-2 rounded-md px-3 py-2 text-sm transition-colors ${
                  tab === t.key
                    ? "bg-primary/10 text-primary font-medium"
                    : "text-muted-foreground hover:bg-muted"
                }`}
              >
                <Icon className="h-4 w-4" />
                {t.label}
              </button>
            );
          })}
        </div>

        {/* Tab content */}
        <div className="flex-1">
          {tab === "api" && <APIKeysSettings />}
          {tab === "scan" && <ScanProfileSettings />}
          {tab === "llm" && <LLMSettings />}
          {tab === "integrations" && <IntegrationSettings />}
          {tab === "notifications" && <NotificationSettings />}
          {tab === "users" && <UserSettings />}
          {tab === "cerberus" && <CerberusExportSettings />}
        </div>
      </div>
    </div>
  );
}

function APIKeysSettings() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>API Keys</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div>
          <Label>Primary API Key</Label>
          <div className="mt-1 flex gap-2">
            <Input value="argus-key-****-****-****-7f3a" readOnly className="font-mono" />
            <Button variant="outline" size="sm">Regenerate</Button>
          </div>
          <p className="mt-1 text-xs text-muted-foreground">Used for API access and CLI authentication</p>
        </div>
        <div>
          <Label>Read-Only Key</Label>
          <div className="mt-1 flex gap-2">
            <Input value="argus-ro-****-****-****-2e1b" readOnly className="font-mono" />
            <Button variant="outline" size="sm">Regenerate</Button>
          </div>
          <p className="mt-1 text-xs text-muted-foreground">Viewer access — can read findings but cannot run scans</p>
        </div>
        <Button className="gap-2"><Save className="h-4 w-4" />Save Changes</Button>
      </CardContent>
    </Card>
  );
}

function ScanProfileSettings() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Scan Profiles</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {[
          { name: "Full Scan", agents: 12, desc: "All 12 agents, all techniques" },
          { name: "Quick Scan", agents: 5, desc: "Top 5 priority agents, limited techniques" },
          { name: "Stealth Scan", agents: 12, desc: "All agents, rate-limited to avoid detection" },
          { name: "Phase 5 Only", agents: 2, desc: "Persona Hijacking + Memory Boundary Collapse" },
        ].map((p) => (
          <div key={p.name} className="flex items-center justify-between rounded-md border border-border p-3">
            <div>
              <p className="text-sm font-medium">{p.name}</p>
              <p className="text-xs text-muted-foreground">{p.desc}</p>
            </div>
            <div className="flex items-center gap-2">
              <Badge variant="secondary">{p.agents} agents</Badge>
              <Button variant="outline" size="sm">Edit</Button>
            </div>
          </div>
        ))}
        <Button variant="outline" className="w-full">+ Create Scan Profile</Button>
      </CardContent>
    </Card>
  );
}

function LLMSettings() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>LLM Configuration</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div>
          <Label>LLM Provider</Label>
          <Select defaultValue="openai">
            <SelectTrigger className="mt-1">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="openai">OpenAI</SelectItem>
              <SelectItem value="anthropic">Anthropic</SelectItem>
              <SelectItem value="ollama">Ollama (Local)</SelectItem>
              <SelectItem value="azure">Azure OpenAI</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div>
          <Label>Model</Label>
          <Input defaultValue="gpt-4" className="mt-1" />
        </div>
        <div>
          <Label>API Key</Label>
          <Input type="password" defaultValue="sk-..." className="mt-1 font-mono" />
        </div>
        <div>
          <Label>Temperature</Label>
          <Input type="number" defaultValue="0.7" step="0.1" min="0" max="2" className="mt-1 w-24" />
        </div>
        <div>
          <Label>Max Tokens</Label>
          <Input type="number" defaultValue="4096" className="mt-1 w-32" />
        </div>
        <Button className="gap-2"><Save className="h-4 w-4" />Save Changes</Button>
      </CardContent>
    </Card>
  );
}

function IntegrationSettings() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Integrations</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {[
          { name: "Slack", desc: "Send alerts to Slack channels", connected: true },
          { name: "Jira", desc: "Auto-create tickets for findings", connected: false },
          { name: "PagerDuty", desc: "Alert on-call for CRITICAL findings", connected: false },
          { name: "Webhook", desc: "Send findings to custom endpoints", connected: true },
          { name: "SIEM Export", desc: "Forward to Splunk / Sentinel / etc.", connected: false },
        ].map((i) => (
          <div key={i.name} className="flex items-center justify-between rounded-md border border-border p-3">
            <div>
              <p className="text-sm font-medium">{i.name}</p>
              <p className="text-xs text-muted-foreground">{i.desc}</p>
            </div>
            <div className="flex items-center gap-2">
              {i.connected ? (
                <Badge className="bg-green-600">Connected</Badge>
              ) : (
                <Badge variant="secondary">Not Connected</Badge>
              )}
              <Button variant="outline" size="sm">Configure</Button>
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

function NotificationSettings() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Notification Preferences</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {[
          { label: "New CRITICAL finding", desc: "Alert immediately on critical severity", default: true },
          { label: "Scan complete", desc: "Notify when a scan finishes", default: true },
          { label: "Target regression", desc: "Alert when a previously clean target fails", default: true },
          { label: "Persona drift detected", desc: "Alert when persona baseline deviation exceeds threshold", default: true },
          { label: "Memory boundary leak", desc: "Alert when canary tokens cross boundaries", default: true },
          { label: "New compound chain", desc: "Alert when correlation engine discovers a new attack path", default: false },
          { label: "Scheduled scan failed", desc: "Alert when a recurring scan fails to run", default: true },
        ].map((n) => (
          <div key={n.label} className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium">{n.label}</p>
              <p className="text-xs text-muted-foreground">{n.desc}</p>
            </div>
            <Switch defaultChecked={n.default} />
          </div>
        ))}
        <Button className="gap-2"><Save className="h-4 w-4" />Save Preferences</Button>
      </CardContent>
    </Card>
  );
}

function UserSettings() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>User Management</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {[
          { name: "admin@odingard.com", role: "Operator", lastActive: "2h ago" },
          { name: "analyst@client.com", role: "Viewer", lastActive: "1d ago" },
        ].map((u) => (
          <div key={u.name} className="flex items-center justify-between rounded-md border border-border p-3">
            <div>
              <p className="text-sm font-medium">{u.name}</p>
              <p className="text-xs text-muted-foreground">Last active: {u.lastActive}</p>
            </div>
            <div className="flex items-center gap-2">
              <Badge variant="secondary">{u.role}</Badge>
              <Button variant="outline" size="sm">Edit</Button>
            </div>
          </div>
        ))}
        <Button variant="outline" className="w-full">+ Invite User</Button>
      </CardContent>
    </Card>
  );
}

function CerberusExportSettings() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>CERBERUS Export</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-sm text-muted-foreground">
          Export ARGUS findings as CERBERUS detection rules for deployment in the defensive product.
          Rules are auto-generated from validated findings with compound attack chain context.
        </p>
        <div>
          <Label>Export Format</Label>
          <Select defaultValue="cerberus-native">
            <SelectTrigger className="mt-1">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="cerberus-native">CERBERUS Native</SelectItem>
              <SelectItem value="sigma">Sigma Rules</SelectItem>
              <SelectItem value="yara">YARA Rules</SelectItem>
              <SelectItem value="json">JSON (Generic)</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div>
          <Label>Include Findings</Label>
          <Select defaultValue="validated-only">
            <SelectTrigger className="mt-1">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="validated-only">Validated Only</SelectItem>
              <SelectItem value="high-confidence">High Confidence (VW &gt; 0.7)</SelectItem>
              <SelectItem value="all">All Findings</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="flex items-center gap-2">
          <Switch defaultChecked />
          <Label>Include compound chain context</Label>
        </div>
        <div className="flex items-center gap-2">
          <Switch defaultChecked />
          <Label>Include ALEC evidence references</Label>
        </div>
        <Button className="gap-2"><FileDown className="h-4 w-4" />Export Rules</Button>
      </CardContent>
    </Card>
  );
}
