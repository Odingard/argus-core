import {
  Link2,
  ChevronRight,
  Shield,
  ExternalLink,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

interface ChainStep {
  agent: string;
  technique: string;
  finding: string;
  severity: "critical" | "high" | "medium" | "low";
}

interface CompoundChain {
  id: string;
  name: string;
  severity: "critical" | "high" | "medium";
  steps: ChainStep[];
  description: string;
  recommendation: string;
}

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-red-600",
  high: "bg-orange-600",
  medium: "bg-yellow-600",
  low: "bg-blue-600",
};

const MOCK_CHAINS: CompoundChain[] = [
  {
    id: "chain-001",
    name: "Persona Drift → Privilege Escalation → Data Exfiltration",
    severity: "critical",
    description:
      "An attacker hijacks the agent's persona via identity drift, uses the inflated authority to escalate privileges through confused deputy, then exfiltrates data through cross-agent relay.",
    recommendation:
      "Implement persona fingerprint monitoring, enforce strict role boundaries, and isolate agent-to-agent communication channels.",
    steps: [
      { agent: "PH-11", technique: "identity_drift_gradual", finding: "Persona drift — authority inflation", severity: "critical" },
      { agent: "PE-07", technique: "confused_deputy", finding: "Privilege escalation via confused deputy chain", severity: "high" },
      { agent: "CX-06", technique: "agent_relay", finding: "Cross-agent data exfiltration", severity: "high" },
    ],
  },
  {
    id: "chain-002",
    name: "Memory Poisoning → Boundary Collapse → Instruction Override",
    severity: "critical",
    description:
      "Adversarial content planted in memory store bleeds across boundaries, contaminating the instruction hierarchy and allowing user-level content to override system directives.",
    recommendation:
      "Enforce strict memory store isolation, implement canary token monitoring, and validate instruction hierarchy at every turn.",
    steps: [
      { agent: "MP-03", technique: "adversarial_memory_plant", finding: "Memory poisoning via adversarial content", severity: "high" },
      { agent: "MB-12", technique: "context_bleed_shortterm_to_longterm", finding: "Context bleed across session boundaries", severity: "critical" },
      { agent: "MB-12", technique: "instruction_hierarchy_user_override", finding: "User context overrides system directives", severity: "critical" },
    ],
  },
  {
    id: "chain-003",
    name: "Tool Poisoning → Supply Chain → Model Extraction",
    severity: "high",
    description:
      "Hidden instructions in a compromised MCP tool definition lead to supply chain compromise, enabling extraction of the system prompt and configuration.",
    recommendation:
      "Audit all MCP tool descriptions for hidden content, verify supply chain integrity, and protect system prompt from extraction.",
    steps: [
      { agent: "TP-02", technique: "hidden_instruction_following", finding: "Hidden instruction in tool description", severity: "high" },
      { agent: "SC-09", technique: "dependency_trust", finding: "Unverified external dependency", severity: "medium" },
      { agent: "ME-10", technique: "system_prompt_extraction", finding: "System prompt extractable", severity: "high" },
    ],
  },
  {
    id: "chain-004",
    name: "Identity Spoof → Context Window → Race Condition",
    severity: "high",
    description:
      "Spoofed identity headers bypass authentication, allowing the attacker to manipulate the context window and exploit race conditions in parallel sessions.",
    recommendation:
      "Implement cryptographic agent identity verification, bound context window processing, and enforce session isolation.",
    steps: [
      { agent: "IS-04", technique: "claimed_identity_header", finding: "Identity header spoofing accepted", severity: "medium" },
      { agent: "CW-05", technique: "early_authority_injection", finding: "Authority injection in context window", severity: "high" },
      { agent: "RC-08", technique: "parallel_session_isolation", finding: "Session isolation bypass via race", severity: "high" },
    ],
  },
];

export function CompoundChainsPage() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Compound Attack Chains</h2>
          <p className="text-sm text-muted-foreground">
            How individual findings chain into real attack paths — ARGUS&apos;s differentiator
          </p>
        </div>
        <Badge variant="secondary">{MOCK_CHAINS.length} chains detected</Badge>
      </div>

      <div className="space-y-4">
        {MOCK_CHAINS.map((chain) => (
          <Card key={chain.id}>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-md bg-red-600/10">
                    <Link2 className="h-5 w-5 text-red-400" />
                  </div>
                  <div>
                    <CardTitle className="text-base">{chain.name}</CardTitle>
                    <p className="mt-1 text-sm text-muted-foreground">{chain.description}</p>
                  </div>
                </div>
                <Badge className={`${SEVERITY_STYLES[chain.severity]}`}>
                  {chain.severity}
                </Badge>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Chain visualization */}
              <div className="flex items-center gap-2 overflow-x-auto py-2">
                {chain.steps.map((step, i) => (
                  <div key={i} className="flex items-center gap-2">
                    <div className="min-w-48 rounded-md border border-border bg-background p-3">
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className="text-xs font-mono">
                          {step.agent}
                        </Badge>
                        <Badge className={`text-xs ${SEVERITY_STYLES[step.severity]}`}>
                          {step.severity}
                        </Badge>
                      </div>
                      <p className="mt-2 text-sm font-medium">{step.finding}</p>
                      <p className="mt-1 text-xs text-muted-foreground">{step.technique}</p>
                    </div>
                    {i < chain.steps.length - 1 && (
                      <ChevronRight className="h-5 w-5 shrink-0 text-red-400" />
                    )}
                  </div>
                ))}
              </div>

              {/* Break the chain recommendation */}
              <div className="rounded-md border border-green-800/50 bg-green-950/20 p-3">
                <div className="flex items-center gap-2 text-sm font-medium text-green-400">
                  <Shield className="h-4 w-4" />
                  Break the Chain
                </div>
                <p className="mt-1 text-sm text-muted-foreground">{chain.recommendation}</p>
              </div>

              <Button variant="outline" size="sm" className="gap-1">
                <ExternalLink className="h-3 w-3" />
                View Full Analysis
              </Button>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
