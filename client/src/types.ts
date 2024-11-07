export type RiskLevel = "critical" | "high" | "medium" | "low" | "none";

export type MutationStrategy =
  | "jailbreak_prefix"
  | "role_play"
  | "code_injection"
  | "prompt_injection"
  | "adversarial_suffix"
  | "token_smuggling"
  | "base64_encoding"
  | "language_switch"
  | "hypothetical_framing"
  | "chain_of_thought_manipulation";

export type AttackCategory =
  | "jailbreak"
  | "prompt_injection"
  | "data_exfiltration"
  | "hallucination"
  | "bias_amplification"
  | "harmful_content"
  | "code_execution";

export interface Attack {
  id: string;
  category: AttackCategory;
  strategy: MutationStrategy;
  prompt: string;
  description: string;
  severity: RiskLevel;
  tags: string[];
}

export interface AttackResult {
  attackId: string;
  attack: Attack;
  modelResponse: string;
  passed: boolean;          // true = model resisted the attack
  riskLevel: RiskLevel;
  detectionScore: number;   // 0.0–1.0
  latencyMs: number;
  timestamp: string;        // ISO-8601
  reasoning: string;
}

export interface AuditSummary {
  totalAttacks: number;
  passed: number;           // attacks resisted
  failed: number;           // attacks succeeded (safety failures)
  criticalFailures: number;
  highFailures: number;
  mediumFailures: number;
  lowFailures: number;
  overallRiskLevel: RiskLevel;
  safetyScore: number;      // 0–100
  durationMs: number;
}

export interface AuditResult {
  auditId: string;
  modelEndpoint: string;
  modelName?: string;
  startedAt: string;        // ISO-8601
  completedAt: string;      // ISO-8601
  summary: AuditSummary;
  results: AttackResult[];
  metadata: Record<string, string>;
}

export interface AuditRequest {
  modelEndpoint: string;
  attackCount: number;
  categories?: AttackCategory[];
  strategies?: MutationStrategy[];
  timeoutMs?: number;
  parallelWorkers?: number;
}

export interface ApiError {
  status: number;
  code: string;
  message: string;
  detail?: unknown;
}

export interface AuditClientConfig {
  baseUrl: string;
  apiKey?: string;
  timeoutMs: number;
  retries: number;
}
