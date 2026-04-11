import { useState, useEffect, useCallback } from "react";
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
  Plus,
  Trash2,
  AlertTriangle,
  CheckCircle,
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
import { getSettings, saveSettings, getApiKeys, createApiKey, revokeApiKey } from "@/api/client";

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

  const reload = useCallback(async () => {
    try {
      setLoading(true);
      const data = await getSettings();
      setSettings(data.settings || {});
    } catch {
      // Settings endpoint may return empty on first use
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { reload(); }, [reload]);

  if (loading) {
    return (<div className="flex items-center justify-center py-20"><Loader2 className="h-8 w-8 animate-spin text-primary" /></div>);
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Settings</h2>
        <p className="text-sm text-muted-foreground">
          Platform configuration — all data loaded from database
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

        {/* Tab content — all wired to real backend API */}
        <div className="flex-1">
          {tab === "api" && <APIKeysSettings />}
          {tab === "scan" && <ScanProfileSettings settings={(settings.scan ?? {}) as Record<string, unknown>} />}
          {tab === "llm" && <LLMSettings settings={(settings.llm ?? {}) as Record<string, unknown>} />}
          {tab === "integrations" && <IntegrationSettings settings={(settings.integrations ?? {}) as Record<string, unknown>} />}
          {tab === "notifications" && <NotificationSettings settings={(settings.notifications ?? {}) as Record<string, unknown>} />}
          {tab === "users" && <UserSettings />}
          {tab === "cerberus" && <CerberusExportSettings settings={(settings.cerberus ?? {}) as Record<string, unknown>} />}
        </div>
      </div>
    </div>
  );
}

/* ── API Keys — loaded from /api/auth/keys (real DB) ── */
function APIKeysSettings() {
  const [keys, setKeys] = useState<Record<string, unknown>[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [newKeyName, setNewKeyName] = useState("");
  const [newKeyRole, setNewKeyRole] = useState("read");
  const [saving, setSaving] = useState(false);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const loadKeys = useCallback(async () => {
    try {
      setLoading(true);
      const data = await getApiKeys();
      setKeys(data.api_keys || []);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load API keys");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadKeys(); }, [loadKeys]);

  const handleCreate = async () => {
    if (!newKeyName.trim()) return;
    try {
      setSaving(true);
      await createApiKey({ name: newKeyName.trim(), role: newKeyRole });
      setNewKeyName("");
      setSuccessMsg("API key created");
      setTimeout(() => setSuccessMsg(null), 3000);
      await loadKeys();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create key");
    } finally {
      setSaving(false);
    }
  };

  const handleRevoke = async (keyId: string) => {
    try {
      await revokeApiKey(keyId);
      setSuccessMsg("API key revoked");
      setTimeout(() => setSuccessMsg(null), 3000);
      await loadKeys();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to revoke key");
    }
  };

  if (loading) return <div className="flex justify-center py-8"><Loader2 className="h-6 w-6 animate-spin" /></div>;

  return (
    <Card>
      <CardHeader>
        <CardTitle>API Keys</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {error && (
          <div className="flex items-center gap-2 rounded-md bg-red-500/10 p-3 text-sm text-red-400">
            <AlertTriangle className="h-4 w-4" />{error}
          </div>
        )}
        {successMsg && (
          <div className="flex items-center gap-2 rounded-md bg-green-500/10 p-3 text-sm text-green-400">
            <CheckCircle className="h-4 w-4" />{successMsg}
          </div>
        )}

        {keys.length === 0 ? (
          <p className="text-sm text-muted-foreground">No API keys found. Create one below.</p>
        ) : (
          keys.map((k) => (
            <div key={String(k.id)} className="flex items-center justify-between rounded-md border border-border p-3">
              <div>
                <p className="text-sm font-medium">{String(k.name || "Unnamed")}</p>
                <p className="mt-0.5 font-mono text-xs text-muted-foreground">
                  {String(k.key_prefix || String(k.id || "").slice(0, 12))}...
                </p>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant="secondary">{String(k.role || "read")}</Badge>
                <Badge variant="outline" className="text-xs">{k.is_active ? "Active" : "Revoked"}</Badge>
                {k.is_active && (
                  <Button variant="outline" size="sm" className="gap-1 text-red-400" onClick={() => handleRevoke(String(k.id))}>
                    <Trash2 className="h-3 w-3" />Revoke
                  </Button>
                )}
              </div>
            </div>
          ))
        )}

        <div className="border-t border-border pt-4">
          <p className="mb-2 text-sm font-medium">Create New API Key</p>
          <div className="flex gap-2">
            <Input placeholder="Key name" value={newKeyName} onChange={(e) => setNewKeyName(e.target.value)} className="flex-1" />
            <Select value={newKeyRole} onValueChange={setNewKeyRole}>
              <SelectTrigger className="w-32"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="read">Read</SelectItem>
                <SelectItem value="write">Write</SelectItem>
                <SelectItem value="admin">Admin</SelectItem>
              </SelectContent>
            </Select>
            <Button onClick={handleCreate} disabled={saving || !newKeyName.trim()} className="gap-1">
              {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
              Create
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

/* ── Generic settings section hook — loads/saves from /api/settings/{section} ── */
function useSettingsSection(section: string, initial: Record<string, unknown>) {
  const [values, setValues] = useState<Record<string, unknown>>(initial);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => { setValues(initial); }, [initial]);

  const update = (key: string, val: unknown) => {
    setValues((prev) => ({ ...prev, [key]: val }));
    setSaved(false);
  };

  const save = async () => {
    try {
      setSaving(true);
      setError(null);
      await saveSettings(section, values);
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save");
    } finally {
      setSaving(false);
    }
  };

  return { values, update, save, saving, saved, error };
}

/* ── Scan Profiles — loaded from /api/settings/scan ── */
function ScanProfileSettings({ settings }: { settings: Record<string, unknown> }) {
  const { values, update, save, saving, saved, error } = useSettingsSection("scan", settings);
  const profiles = (values.profiles ?? []) as { name: string; agents: number; desc: string }[];

  const addProfile = () => {
    update("profiles", [...profiles, { name: "New Profile", agents: 12, desc: "Custom scan profile" }]);
  };

  const removeProfile = (idx: number) => {
    update("profiles", profiles.filter((_, i) => i !== idx));
  };

  return (
    <Card>
      <CardHeader><CardTitle>Scan Profiles</CardTitle></CardHeader>
      <CardContent className="space-y-4">
        {error && <p className="text-sm text-red-400">{error}</p>}
        {profiles.length === 0 ? (
          <p className="text-sm text-muted-foreground">No scan profiles configured. Add one below.</p>
        ) : (
          profiles.map((p, idx) => (
            <div key={idx} className="flex items-center justify-between rounded-md border border-border p-3">
              <div className="flex-1 space-y-1">
                <Input value={p.name} onChange={(e) => {
                  const updated = [...profiles];
                  updated[idx] = { ...updated[idx], name: e.target.value };
                  update("profiles", updated);
                }} className="h-7 border-none bg-transparent p-0 text-sm font-medium" />
                <Input value={p.desc} onChange={(e) => {
                  const updated = [...profiles];
                  updated[idx] = { ...updated[idx], desc: e.target.value };
                  update("profiles", updated);
                }} className="h-6 border-none bg-transparent p-0 text-xs text-muted-foreground" />
              </div>
              <div className="flex items-center gap-2">
                <Badge variant="secondary">{p.agents} agents</Badge>
                <Button variant="outline" size="sm" className="text-red-400" onClick={() => removeProfile(idx)}>
                  <Trash2 className="h-3 w-3" />
                </Button>
              </div>
            </div>
          ))
        )}
        <Button variant="outline" className="w-full gap-1" onClick={addProfile}><Plus className="h-3 w-3" />Add Scan Profile</Button>
        <Button onClick={save} disabled={saving} className="gap-2">
          {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : saved ? <CheckCircle className="h-4 w-4" /> : <Save className="h-4 w-4" />}
          {saved ? "Saved" : "Save Changes"}
        </Button>
      </CardContent>
    </Card>
  );
}

/* ── LLM Config — loaded from /api/settings/llm ── */
function LLMSettings({ settings }: { settings: Record<string, unknown> }) {
  const { values, update, save, saving, saved, error } = useSettingsSection("llm", settings);

  return (
    <Card>
      <CardHeader><CardTitle>LLM Configuration</CardTitle></CardHeader>
      <CardContent className="space-y-4">
        {error && <p className="text-sm text-red-400">{error}</p>}
        <div>
          <Label>LLM Provider</Label>
          <Select value={String(values.provider || "")} onValueChange={(v) => update("provider", v)}>
            <SelectTrigger className="mt-1"><SelectValue placeholder="Select provider" /></SelectTrigger>
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
          <Input value={String(values.model || "")} onChange={(e) => update("model", e.target.value)} className="mt-1" placeholder="e.g. gpt-4" />
        </div>
        <div>
          <Label>API Key</Label>
          <Input type="password" value={String(values.api_key || "")} onChange={(e) => update("api_key", e.target.value)} className="mt-1 font-mono" placeholder="Enter API key" />
        </div>
        <div>
          <Label>Temperature</Label>
          <Input type="number" value={String(values.temperature ?? "")} onChange={(e) => update("temperature", parseFloat(e.target.value) || 0)} step="0.1" min="0" max="2" className="mt-1 w-24" placeholder="0.7" />
        </div>
        <div>
          <Label>Max Tokens</Label>
          <Input type="number" value={String(values.max_tokens ?? "")} onChange={(e) => update("max_tokens", parseInt(e.target.value) || 0)} className="mt-1 w-32" placeholder="4096" />
        </div>
        <Button onClick={save} disabled={saving} className="gap-2">
          {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : saved ? <CheckCircle className="h-4 w-4" /> : <Save className="h-4 w-4" />}
          {saved ? "Saved" : "Save Changes"}
        </Button>
      </CardContent>
    </Card>
  );
}

/* ── Integrations — loaded from /api/settings/integrations ── */
function IntegrationSettings({ settings }: { settings: Record<string, unknown> }) {
  const { values, update, save, saving, saved, error } = useSettingsSection("integrations", settings);
  const integrations = (values.items ?? []) as { name: string; desc: string; enabled: boolean; config: string }[];

  const toggleIntegration = (idx: number) => {
    const updated = [...integrations];
    updated[idx] = { ...updated[idx], enabled: !updated[idx].enabled };
    update("items", updated);
  };

  const updateConfig = (idx: number, config: string) => {
    const updated = [...integrations];
    updated[idx] = { ...updated[idx], config };
    update("items", updated);
  };

  return (
    <Card>
      <CardHeader><CardTitle>Integrations</CardTitle></CardHeader>
      <CardContent className="space-y-4">
        {error && <p className="text-sm text-red-400">{error}</p>}
        {integrations.length === 0 ? (
          <p className="text-sm text-muted-foreground">No integrations configured. Save to initialize defaults.</p>
        ) : (
          integrations.map((i, idx) => (
            <div key={idx} className="rounded-md border border-border p-3 space-y-2">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium">{i.name}</p>
                  <p className="text-xs text-muted-foreground">{i.desc}</p>
                </div>
                <div className="flex items-center gap-2">
                  {i.enabled ? (
                    <Badge className="bg-green-600">Enabled</Badge>
                  ) : (
                    <Badge variant="secondary">Disabled</Badge>
                  )}
                  <Switch checked={i.enabled} onCheckedChange={() => toggleIntegration(idx)} />
                </div>
              </div>
              {i.enabled && (
                <Input value={i.config || ""} onChange={(e) => updateConfig(idx, e.target.value)} placeholder="Configuration (webhook URL, API key, etc.)" className="text-xs" />
              )}
            </div>
          ))
        )}
        <Button onClick={save} disabled={saving} className="gap-2">
          {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : saved ? <CheckCircle className="h-4 w-4" /> : <Save className="h-4 w-4" />}
          {saved ? "Saved" : "Save Changes"}
        </Button>
      </CardContent>
    </Card>
  );
}

/* ── Notifications — loaded from /api/settings/notifications ── */
function NotificationSettings({ settings }: { settings: Record<string, unknown> }) {
  const { values, update, save, saving, saved, error } = useSettingsSection("notifications", settings);

  const NOTIFICATION_TYPES = [
    { key: "critical_finding", label: "New CRITICAL finding", desc: "Alert immediately on critical severity" },
    { key: "scan_complete", label: "Scan complete", desc: "Notify when a scan finishes" },
    { key: "target_regression", label: "Target regression", desc: "Alert when a previously clean target fails" },
    { key: "persona_drift", label: "Persona drift detected", desc: "Alert when persona baseline deviation exceeds threshold" },
    { key: "memory_leak", label: "Memory boundary leak", desc: "Alert when canary tokens cross boundaries" },
    { key: "compound_chain", label: "New compound chain", desc: "Alert when correlation engine discovers a new attack path" },
    { key: "scheduled_fail", label: "Scheduled scan failed", desc: "Alert when a recurring scan fails to run" },
  ];

  return (
    <Card>
      <CardHeader><CardTitle>Notification Preferences</CardTitle></CardHeader>
      <CardContent className="space-y-4">
        {error && <p className="text-sm text-red-400">{error}</p>}
        {NOTIFICATION_TYPES.map((n) => (
          <div key={n.key} className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium">{n.label}</p>
              <p className="text-xs text-muted-foreground">{n.desc}</p>
            </div>
            <Switch
              checked={values[n.key] !== false}
              onCheckedChange={(checked) => update(n.key, checked)}
            />
          </div>
        ))}
        <Button onClick={save} disabled={saving} className="gap-2">
          {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : saved ? <CheckCircle className="h-4 w-4" /> : <Save className="h-4 w-4" />}
          {saved ? "Saved" : "Save Preferences"}
        </Button>
      </CardContent>
    </Card>
  );
}

/* ── Users — loaded from /api/auth/keys (same API keys = users with roles) ── */
function UserSettings() {
  const [keys, setKeys] = useState<Record<string, unknown>[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        setLoading(true);
        const data = await getApiKeys();
        setKeys(data.api_keys || []);
      } catch {
        // may fail if not admin
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  if (loading) return <div className="flex justify-center py-8"><Loader2 className="h-6 w-6 animate-spin" /></div>;

  return (
    <Card>
      <CardHeader><CardTitle>User Management</CardTitle></CardHeader>
      <CardContent className="space-y-4">
        <p className="text-xs text-muted-foreground">Users are identified by their API keys. Each key has a role that determines access level.</p>
        {keys.length === 0 ? (
          <p className="text-sm text-muted-foreground">No API keys / users found.</p>
        ) : (
          keys.map((k) => (
            <div key={String(k.id)} className="flex items-center justify-between rounded-md border border-border p-3">
              <div>
                <p className="text-sm font-medium">{String(k.name || "Unnamed Key")}</p>
                <p className="text-xs text-muted-foreground">
                  Created: {k.created_at ? new Date(String(k.created_at)).toLocaleString() : "N/A"}
                </p>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant="secondary">{String(k.role || "read")}</Badge>
                <Badge variant="outline" className="text-xs">{k.is_active ? "Active" : "Revoked"}</Badge>
              </div>
            </div>
          ))
        )}
        <p className="text-xs text-muted-foreground">To add users, create API keys in the API Keys tab.</p>
      </CardContent>
    </Card>
  );
}

/* ── CERBERUS Export — loaded from /api/settings/cerberus ── */
function CerberusExportSettings({ settings }: { settings: Record<string, unknown> }) {
  const { values, update, save, saving, saved, error } = useSettingsSection("cerberus", settings);

  return (
    <Card>
      <CardHeader><CardTitle>CERBERUS Export</CardTitle></CardHeader>
      <CardContent className="space-y-4">
        {error && <p className="text-sm text-red-400">{error}</p>}
        <p className="text-sm text-muted-foreground">
          Export ARGUS findings as CERBERUS detection rules. Settings are saved to the database.
        </p>
        <div>
          <Label>Export Format</Label>
          <Select value={String(values.format || "")} onValueChange={(v) => update("format", v)}>
            <SelectTrigger className="mt-1"><SelectValue placeholder="Select format" /></SelectTrigger>
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
          <Select value={String(values.include_findings || "")} onValueChange={(v) => update("include_findings", v)}>
            <SelectTrigger className="mt-1"><SelectValue placeholder="Select filter" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="validated-only">Validated Only</SelectItem>
              <SelectItem value="high-confidence">High Confidence (VW &gt; 0.7)</SelectItem>
              <SelectItem value="all">All Findings</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="flex items-center gap-2">
          <Switch checked={values.include_chain_context !== false} onCheckedChange={(v) => update("include_chain_context", v)} />
          <Label>Include compound chain context</Label>
        </div>
        <div className="flex items-center gap-2">
          <Switch checked={values.include_alec_refs !== false} onCheckedChange={(v) => update("include_alec_refs", v)} />
          <Label>Include ALEC evidence references</Label>
        </div>
        <Button onClick={save} disabled={saving} className="gap-2">
          {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : saved ? <CheckCircle className="h-4 w-4" /> : <Save className="h-4 w-4" />}
          {saved ? "Saved" : "Save Settings"}
        </Button>
        <Button variant="outline" className="gap-2"><FileDown className="h-4 w-4" />Export Rules</Button>
      </CardContent>
    </Card>
  );
}
