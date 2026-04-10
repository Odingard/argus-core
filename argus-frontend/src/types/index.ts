// ARGUS Platform Types

export type ScanStatus = "running" | "completed" | "failed" | "pending" | "cancelled";
export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";
export type FindingStatus = "new" | "validated" | "triaged" | "resolved" | "false_positive";
export type TargetType = "mcp_server" | "ai_agent" | "pipeline" | "memory_store";
export type AgentStatus = "idle" | "running" | "completed" | "error";

export interface Agent {
  id: string;
  name: string;
  code: string;
  type: string;
  status: AgentStatus;
  findingsCount: number;
  validatedCount: number;
  techniquesAttempted: number;
  phase: number;
}

export interface Target {
  id: string;
  name: string;
  type: TargetType;
  endpoint: string;
  status: "healthy" | "degraded" | "unreachable" | "unknown";
  lastScanned: string | null;
  findingsCount: number;
  riskScore: number;
  scheduleFrequency: string | null;
  baselineDate: string | null;
  tags: string[];
}

export interface Finding {
  id: string;
  scanId: string;
  agentType: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  status: FindingStatus;
  targetSurface: string;
  technique: string;
  owaspCategory: string;
  verdictWeight: number;
  consequenceWeight: number;
  createdAt: string;
  validatedAt: string | null;
  reproductionSteps: ReproductionStep[];
  attackChain: AttackChainStep[];
}

export interface ReproductionStep {
  stepNumber: number;
  action: string;
  expectedResult: string;
  actualResult?: string;
}

export interface AttackChainStep {
  stepNumber: number;
  agentType: string;
  technique: string;
  description: string;
  targetSurface?: string;
}

export interface CompoundChain {
  id: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  findingIds: string[];
  findings: Finding[];
  attackPath: AttackChainStep[];
  recommendation: string;
}

export interface Scan {
  id: string;
  targetName: string;
  targetEndpoint: string;
  status: ScanStatus;
  startedAt: string;
  completedAt: string | null;
  agentsDeployed: number;
  findingsCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  duration: number | null;
  agents: ScanAgent[];
}

export interface ScanAgent {
  agentType: string;
  status: AgentStatus;
  findingsCount: number;
  startedAt: string;
  completedAt: string | null;
}

export interface CorpusPattern {
  id: string;
  category: string;
  name: string;
  description: string;
  severity: FindingSeverity;
  effectiveness: number;
  usageCount: number;
}

export interface OWASPCoverage {
  category: string;
  code: string;
  description: string;
  findingsCount: number;
  coverage: number;
}

export interface DashboardStats {
  totalScans: number;
  totalFindings: number;
  criticalFindings: number;
  activeTargets: number;
  agentsOnline: number;
  compoundChains: number;
  lastScanTime: string | null;
  trendData: TrendPoint[];
  severityDistribution: SeverityCount[];
  topAgents: AgentPerformance[];
}

export interface TrendPoint {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

export interface SeverityCount {
  severity: FindingSeverity;
  count: number;
}

export interface AgentPerformance {
  agentType: string;
  agentName: string;
  findingsCount: number;
  avgVerdictWeight: number;
}

export interface ScheduledScan {
  id: string;
  targetId: string;
  targetName: string;
  frequency: "hourly" | "daily" | "weekly" | "monthly";
  nextRun: string;
  lastRun: string | null;
  enabled: boolean;
  agents: string[];
}

export interface AlertItem {
  id: string;
  type: "new_critical" | "regression" | "drift_detected" | "scan_complete" | "target_unreachable";
  title: string;
  message: string;
  severity: FindingSeverity;
  timestamp: string;
  read: boolean;
  targetId?: string;
  scanId?: string;
  findingId?: string;
}
