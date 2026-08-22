/**
 * Convenience aliases over the generated types.
 *
 * `types.generated.ts` is rebuilt from the JSON schema and names things after the Pydantic
 * models; this module gives the SDK a stable vocabulary that survives a regeneration.
 */

import type {
  Decision as GeneratedDecision,
  Evidence as GeneratedEvidence,
  Finding as GeneratedFinding,
  FindingResult as GeneratedFindingResult,
  InvestigationResult as GeneratedInvestigationResult,
  InvestigationSchema,
  Observable as GeneratedObservable,
  ObservableResult as GeneratedObservableResult,
  Relation as GeneratedRelation,
  Tag as GeneratedTag,
  ThreatIntel as GeneratedThreatIntel,
} from "./types.generated";

export type Investigation = InvestigationSchema;
export type Observable = GeneratedObservable;
export type Relation = GeneratedRelation;
export type ThreatIntel = GeneratedThreatIntel;
export type Evidence = GeneratedEvidence;
export type Finding = GeneratedFinding;
export type Decision = GeneratedDecision;
export type Tag = GeneratedTag;
export type ObservableResult = GeneratedObservableResult;
export type FindingResult = GeneratedFindingResult;
export type InvestigationResult = GeneratedInvestigationResult;

export type { Verdict } from "./types.generated";
