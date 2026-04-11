import { useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import {
  Activity,
  Target,
  Shield,
  Settings,
  ChevronDown,
  ChevronRight,
  Radio,
  Clock,
  CheckCircle,
  Server,
  Bot,
  GitBranch,
  Database,
  AlertTriangle,
  Link2,
  BarChart3,
  BookOpen,
  Sword,
  Gauge,
  Eye,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";

interface NavSection {
  title: string;
  icon: React.ElementType;
  items: NavItem[];
}

interface NavItem {
  label: string;
  path: string;
  icon: React.ElementType;
  badge?: number;
}

const NAV_SECTIONS: NavSection[] = [
  {
    title: "ACTIVITY",
    icon: Activity,
    items: [
      { label: "Live Scan", path: "/scan/live", icon: Radio },
      { label: "Pending", path: "/scan/pending", icon: Clock },
      { label: "Completed", path: "/scan/completed", icon: CheckCircle },
    ],
  },
  {
    title: "TARGETS",
    icon: Target,
    items: [
      { label: "MCP Servers", path: "/targets/mcp-servers", icon: Server },
      { label: "AI Agents", path: "/targets/ai-agents", icon: Bot },
      { label: "Pipelines", path: "/targets/pipelines", icon: GitBranch },
      { label: "Memory Stores", path: "/targets/memory-stores", icon: Database },
    ],
  },
  {
    title: "FINDINGS",
    icon: Shield,
    items: [
      { label: "All Findings", path: "/findings", icon: AlertTriangle },
      { label: "Compound Chains", path: "/findings/chains", icon: Link2 },
      { label: "OWASP Mapping", path: "/findings/owasp", icon: BarChart3 },
    ],
  },
  {
    title: "PLATFORM",
    icon: Settings,
    items: [
      { label: "Attack Corpus", path: "/platform/corpus", icon: BookOpen },
      { label: "ARGUS Gauntlet", path: "/platform/gauntlet", icon: Sword },
      { label: "Monitoring", path: "/platform/monitoring", icon: Gauge },
      { label: "Settings", path: "/platform/settings", icon: Settings },
    ],
  },
];

export function Sidebar() {
  const location = useLocation();
  const navigate = useNavigate();
  const [expanded, setExpanded] = useState<Record<string, boolean>>({
    ACTIVITY: true,
    TARGETS: true,
    FINDINGS: true,
    PLATFORM: true,
  });

  const toggle = (title: string) =>
    setExpanded((prev) => ({ ...prev, [title]: !prev[title] }));

  return (
    <div className="flex h-full w-60 flex-col border-r border-border bg-card">
      {/* Logo */}
      <div className="flex items-center gap-2 border-b border-border px-4 py-4">
        <Eye className="h-6 w-6 text-primary" />
        <div>
          <h1 className="text-lg font-bold tracking-tight text-primary">ARGUS</h1>
          <p className="text-xs text-muted-foreground">Continuous AI Security</p>
        </div>
      </div>

      {/* Dashboard link */}
      <div className="px-2 pt-2">
        <button
          onClick={() => navigate("/")}
          className={cn(
            "flex w-full items-center gap-2 rounded-md px-3 py-2 text-sm font-medium transition-colors",
            location.pathname === "/"
              ? "bg-primary/10 text-primary"
              : "text-muted-foreground hover:bg-accent hover:text-foreground"
          )}
        >
          <Gauge className="h-4 w-4" />
          Dashboard
        </button>
      </div>

      {/* Navigation sections */}
      <ScrollArea className="flex-1 px-2 py-2">
        {NAV_SECTIONS.map((section) => (
          <div key={section.title} className="mb-1">
            <button
              onClick={() => toggle(section.title)}
              className="flex w-full items-center gap-2 rounded-md px-3 py-1.5 text-xs font-semibold uppercase tracking-wider text-muted-foreground hover:text-foreground"
            >
              {expanded[section.title] ? (
                <ChevronDown className="h-3 w-3" />
              ) : (
                <ChevronRight className="h-3 w-3" />
              )}
              <section.icon className="h-3.5 w-3.5" />
              {section.title}
            </button>

            {expanded[section.title] && (
              <div className="ml-2 space-y-0.5">
                {section.items.map((item) => (
                  <button
                    key={item.path}
                    onClick={() => navigate(item.path)}
                    className={cn(
                      "flex w-full items-center gap-2 rounded-md px-3 py-1.5 text-sm transition-colors",
                      location.pathname === item.path
                        ? "bg-primary/10 text-primary"
                        : "text-muted-foreground hover:bg-accent hover:text-foreground"
                    )}
                  >
                    <item.icon className="h-3.5 w-3.5" />
                    {item.label}
                    {item.badge !== undefined && item.badge > 0 && (
                      <Badge variant="secondary" className="ml-auto text-xs">
                        {item.badge}
                      </Badge>
                    )}
                  </button>
                ))}
              </div>
            )}
          </div>
        ))}
      </ScrollArea>

      {/* Status footer */}
      <div className="border-t border-border px-4 py-3">
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <div className="h-2 w-2 rounded-full bg-green-500" />
          <span>12 Agents Online</span>
        </div>
        <p className="mt-1 text-xs text-muted-foreground/60">Phase 1–5 • v0.9.0</p>
      </div>
    </div>
  );
}
