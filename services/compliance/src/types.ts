export interface BlueprintRef {
  name: string;
  version: string;
}

export type RiskLevel = "minimal" | "limited" | "high";
export type LifecycleStage = "design" | "development" | "deployed" | "retired";
export type RiskRating = "low" | "medium" | "high" | "critical";
export type Level3 = "low" | "medium" | "high";

export interface Stakeholder {
  role: string;
  name: string;
}

/** One version of an AI system inventory record (ISO/IEC 42001 asset register). */
export interface SystemRecord {
  system_id: string;
  version: number;
  name: string;
  purpose: string;
  owner: string;
  risk_level: RiskLevel;
  lifecycle_stage: LifecycleStage;
  blueprints: BlueprintRef[];
  data_categories: string[];
  stakeholders: Stakeholder[];
  created_at: string;
  created_by: string;
  updated_at: string;
  updated_by: string;
}

export interface SystemInput {
  system_id?: string;
  name: string;
  purpose: string;
  owner: string;
  risk_level: RiskLevel;
  lifecycle_stage?: LifecycleStage;
  blueprints?: BlueprintRef[];
  data_categories?: string[];
  stakeholders?: Stakeholder[];
}

export type AssessmentState = "draft" | "in_review" | "approved" | "rejected";

export interface AffectedGroup {
  group: string;
  impact: string;
}

export interface AssessedRisk {
  id: string;
  description: string;
  likelihood: Level3;
  severity: Level3;
  mitigation: string;
  residual: Level3;
}

/** One version of an AI impact assessment (ISO/IEC 42001 Annex A.5; EU AI Act Art. 27 style FRIA content). */
export interface AssessmentRecord {
  assessment_id: string;
  version: number;
  system_id: string;
  title: string;
  state: AssessmentState;
  risk_rating: RiskRating;
  intended_use: string;
  blueprints: BlueprintRef[];
  affected_groups: AffectedGroup[];
  risks: AssessedRisk[];
  stakeholders: Stakeholder[];
  /** The date (YYYY-MM-DD) by which the assessment must be reviewed again. */
  review_due: string;
  author: string;
  /** Everyone who changed this version (including the author). None of them may review it. */
  contributors: string[];
  created_at: string;
  updated_at: string;
  submitted_by: string | null;
  submitted_at: string | null;
  reviewed_by: string | null;
  reviewed_at: string | null;
  review_comment: string | null;
  /** The previous version this one revises, or null for version 1. */
  supersedes: number | null;
}

export interface AssessmentInput {
  system_id: string;
  title: string;
  risk_rating: RiskRating;
  intended_use: string;
  blueprints?: BlueprintRef[];
  affected_groups?: AffectedGroup[];
  risks?: AssessedRisk[];
  stakeholders?: Stakeholder[];
  review_due: string;
}

/** What a client sees: the record plus facts derived at read time (never stored). */
export interface AssessmentView extends AssessmentRecord {
  /** True when the assessment is approved and past its review date, or waiting for review longer than the grace period. */
  overdue: boolean;
  overdue_reason: "review_due_passed" | "review_pending_too_long" | null;
  /** True when a later version exists. */
  superseded: boolean;
}
