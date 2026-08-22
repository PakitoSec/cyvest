/**
 * Entity getters.
 *
 * Everything derived is read from `report`, never recomputed: a v7 document is self-contained
 * precisely so no JavaScript package has to reimplement a scoring rule. If a value the UI needs
 * is missing here, it belongs in the report — not in a helper.
 */

import type {
  Decision,
  Evidence,
  Finding,
  FindingResult,
  Investigation,
  InvestigationResult,
  Observable,
  ObservableResult,
  Relation,
  Tag,
  ThreatIntel,
  Verdict,
} from "./types";

/** Index used by the report to key an observable result by key *and* resolved scope. */
export function observableIndex(observableKey: string, scope?: { scope?: string; fragment_id?: string | null }): string {
  if (!scope || scope.scope === "ALL") return `${observableKey}@ALL`;
  return `${observableKey}@fragment:${scope.fragment_id}`;
}

// --- facts

export function getObservable(inv: Investigation, key: string): Observable | undefined {
  return inv.facts?.observables?.[key];
}

export function getAllObservables(inv: Investigation): Record<string, Observable> {
  return inv.facts?.observables ?? {};
}

export function getRootObservable(inv: Investigation): Observable | undefined {
  const rootKey = inv.header?.root_key;
  return rootKey ? getObservable(inv, rootKey) : undefined;
}

export function getRelation(inv: Investigation, key: string): Relation | undefined {
  return inv.facts?.relations?.[key];
}

export function getAllRelations(inv: Investigation): Record<string, Relation> {
  return inv.facts?.relations ?? {};
}

export function getThreatIntel(inv: Investigation, key: string): ThreatIntel | undefined {
  return inv.facts?.signals?.[key];
}

export function getAllThreatIntels(inv: Investigation): Record<string, ThreatIntel> {
  return inv.facts?.signals ?? {};
}

/** Signals attached to one observable. */
export function getThreatIntelsFor(inv: Investigation, observableKey: string): ThreatIntel[] {
  return Object.values(getAllThreatIntels(inv)).filter((signal) => signal.subject_key === observableKey);
}

export function getFinding(inv: Investigation, key: string): Finding | undefined {
  return inv.facts?.findings?.[key];
}

export function getAllFindings(inv: Investigation): Record<string, Finding> {
  return inv.facts?.findings ?? {};
}

export function getEvidence(inv: Investigation, key: string): Evidence | undefined {
  return inv.facts?.evidences?.[key];
}

export function getAllEvidences(inv: Investigation): Record<string, Evidence> {
  return inv.facts?.evidences ?? {};
}

/** The v6 `Enrichment` is just an evidence type; filter instead of a dedicated accessor. */
export function getEvidencesByType(inv: Investigation, evidenceType: string): Evidence[] {
  return Object.values(getAllEvidences(inv)).filter((evidence) => evidence.evidence_type === evidenceType);
}

export function getDecision(inv: Investigation, key: string): Decision | undefined {
  return inv.decisions?.[key];
}

export function getAllDecisions(inv: Investigation): Record<string, Decision> {
  return inv.decisions ?? {};
}

export function getDecisionsFor(inv: Investigation, targetKey: string): Decision[] {
  return Object.values(getAllDecisions(inv)).filter((decision) => decision.target_key === targetKey);
}

export function isAllowlisted(inv: Investigation, observableKey: string): boolean {
  return getDecisionsFor(inv, observableKey).some((decision) => decision.kind === "ALLOWLISTED");
}

export function getTag(inv: Investigation, key: string): Tag | undefined {
  return inv.tags?.[key];
}

export function getTagByName(inv: Investigation, name: string): Tag | undefined {
  return getTag(inv, `tag:${name.trim().toLowerCase()}`);
}

export function getAllTags(inv: Investigation): Record<string, Tag> {
  return inv.tags ?? {};
}

// --- results

export function getInvestigationResult(inv: Investigation): InvestigationResult {
  return inv.report.investigation;
}

export function getObservableResult(
  inv: Investigation,
  observableKey: string,
  scope?: { scope?: string; fragment_id?: string | null },
): ObservableResult | undefined {
  return inv.report.observables?.[observableIndex(observableKey, scope)];
}

export function getFindingResult(inv: Investigation, findingKey: string): FindingResult | undefined {
  return inv.report.findings?.[findingKey];
}

export function getObservableScore(inv: Investigation, observableKey: string): number {
  return getObservableResult(inv, observableKey)?.score ?? 0;
}

export function getObservableVerdict(inv: Investigation, observableKey: string): Verdict {
  return (getObservableResult(inv, observableKey)?.verdict as Verdict) ?? "INFO";
}

export function getFindingScore(inv: Investigation, findingKey: string): number {
  return getFindingResult(inv, findingKey)?.score ?? 0;
}

export function getFindingVerdict(inv: Investigation, findingKey: string): Verdict {
  return (getFindingResult(inv, findingKey)?.verdict as Verdict) ?? "INFO";
}

export function getGlobalScore(inv: Investigation): number {
  return inv.report.investigation.score ?? 0;
}

export function getGlobalVerdict(inv: Investigation): Verdict {
  return (inv.report.investigation.verdict as Verdict) ?? "INFO";
}

/** True when a decision or a stronger link overrode the computed value. */
export function wasSuppressed(inv: Investigation, key: string): boolean {
  const finding = getFindingResult(inv, key);
  if (finding) return Boolean(finding.suppressed_by_decision || finding.own_term_suppressed);
  return Boolean(getObservableResult(inv, key)?.suppressed_by_decision);
}

/** Findings a tag points at, plus those of every descendant tag. */
export function getTagFindingKeys(inv: Investigation, tagName: string): string[] {
  const prefix = `${tagName}:`;
  const keys = new Set<string>();
  for (const tag of Object.values(getAllTags(inv))) {
    if (tag.name === tagName || tag.name.startsWith(prefix)) {
      for (const key of tag.finding_keys ?? []) keys.add(key);
    }
  }
  return [...keys];
}

/**
 * A tag's aggregated score.
 *
 * This sums values the engine produced; it does not re-derive them. Uncounted findings — not
 * applicable, pending or dismissed — are absent from the sum *and* from any ratio built on it.
 */
export function getTagAggregatedScore(inv: Investigation, tagName: string): number {
  return getTagFindingKeys(inv, tagName).reduce((total, key) => {
    const result = getFindingResult(inv, key);
    return result?.counted ? total + (result.score ?? 0) : total;
  }, 0);
}

export interface InvestigationCounts {
  observables: number;
  relations: number;
  signals: number;
  evidences: number;
  findings: number;
  evaluatedFindings: number;
  decisions: number;
  tags: number;
}

export function getCounts(inv: Investigation): InvestigationCounts {
  return {
    observables: Object.keys(getAllObservables(inv)).length,
    relations: Object.keys(getAllRelations(inv)).length,
    signals: Object.keys(getAllThreatIntels(inv)).length,
    evidences: Object.keys(getAllEvidences(inv)).length,
    findings: Object.keys(getAllFindings(inv)).length,
    evaluatedFindings: Object.values(inv.report.findings ?? {}).filter((result) => result.counted).length,
    decisions: Object.keys(getAllDecisions(inv)).length,
    tags: Object.keys(getAllTags(inv)).length,
  };
}
