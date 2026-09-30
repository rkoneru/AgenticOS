/** Typed view of a schema-valid ABL v1 document. Only use after `validateAbl` succeeded. */
export interface AblModelRef {
  provider: string;
  model: string;
  endpoint?: string;
  params?: { temperature?: number; maxOutputTokens?: number; topP?: number };
}

export interface AblTool {
  name: string;
  kind: "function" | "mcp" | "code" | "browser" | "channel" | "agent";
  ref?: string;
  mcpServer?: string;
  description?: string;
  sideEffects?: "none" | "read" | "write" | "external";
  timeoutSeconds?: number;
}

export interface AblBudget {
  soft?: number;
  hard?: number;
}

export interface AblDocument {
  apiVersion: "abl.axis.dev/v1";
  kind: "Agent";
  metadata: {
    name: string;
    version: string;
    description?: string;
    owner?: string;
    labels?: Record<string, string>;
  };
  spec: {
    riskClassification: {
      level: "minimal" | "limited" | "high";
      rationale: string;
      intendedPurpose?: string;
      transparencyNotice?: string;
      humanOversight?: { required: boolean; approverRoles?: string[] };
    };
    model: { primary: AblModelRef; fallbacks?: AblModelRef[] };
    routing?: { stages?: Array<"cache" | "rules" | "mpm" | "rag" | "llm"> };
    instructions: { system: string };
    tools?: AblTool[];
    memory?: { run?: boolean; session?: boolean; longTerm?: boolean; knowledgeBases?: string[] };
    budgets?: {
      tokens?: AblBudget;
      costUsd?: AblBudget;
      runtimeSeconds?: AblBudget;
      toolCalls?: AblBudget;
    };
    process?: {
      restartPolicy?: "never" | "on-failure" | "always";
      maxRestarts?: number;
      maxChildren?: number;
      timeoutSeconds?: number;
      supervisor?: "one-for-one" | "one-for-all" | "rest-for-one";
    };
    policy?: { packs?: string[] };
    channels?: Array<"web" | "slack" | "teams" | "email" | "sms" | "whatsapp" | "voice">;
    data?: { phi?: boolean; residency?: string };
    evals?: { suites?: Array<{ ref: string; threshold: number }> };
  };
}
