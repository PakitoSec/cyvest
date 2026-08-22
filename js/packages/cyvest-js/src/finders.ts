/**
 * Query helpers.
 *
 * Filters on computed values go through the report; filters on stated values go through the
 * facts. Keeping the two apart is what stops a UI from quietly inventing its own scoring.
 */

import { getAllFindings, getAllObservables, getAllThreatIntels, getFindingResult, getObservableResult } from "./getters";
import type { Finding, Investigation, Observable, ThreatIntel, Verdict } from "./types";
import { confidenceBand, isVerdictAtLeast } from "./verdicts";

// --- observables, by stated properties

export function findObservablesByType(inv: Investigation, type: string): Observable[] {
  return Object.values(getAllObservables(inv)).filter((observable) => observable.type === type);
}

export function findObservablesByValue(inv: Investigation, value: string): Observable[] {
  return Object.values(getAllObservables(inv)).filter((observable) => observable.value === value);
}

export function findObservablesContaining(inv: Investigation, fragment: string): Observable[] {
  const needle = fragment.toLowerCase();
  return Object.values(getAllObservables(inv)).filter((observable) => observable.value.toLowerCase().includes(needle));
}

export function findInternalObservables(inv: Investigation): Observable[] {
  return Object.values(getAllObservables(inv)).filter((observable) => observable.internal === true);
}

export function findExternalObservables(inv: Investigation): Observable[] {
  return Object.values(getAllObservables(inv)).filter((observable) => observable.internal === false);
}

// --- observables, by computed verdict

export function findObservablesByVerdict(inv: Investigation, verdict: Verdict): Observable[] {
  return Object.values(getAllObservables(inv)).filter(
    (observable) => getObservableResult(inv, observable.key)?.verdict === verdict,
  );
}

export function findObservablesAtLeast(inv: Investigation, floor: Verdict): Observable[] {
  return Object.values(getAllObservables(inv)).filter((observable) => {
    const result = getObservableResult(inv, observable.key);
    return result ? isVerdictAtLeast(result.verdict as Verdict, floor) : false;
  });
}

export function findObservablesWithThreatIntel(inv: Investigation): Observable[] {
  const subjects = new Set(Object.values(getAllThreatIntels(inv)).map((signal) => signal.subject_key));
  return Object.values(getAllObservables(inv)).filter((observable) => subjects.has(observable.key));
}

// --- findings

export function findFindingsByVerdict(inv: Investigation, verdict: Verdict): Finding[] {
  return Object.values(getAllFindings(inv)).filter((finding) => getFindingResult(inv, finding.key)?.verdict === verdict);
}

export function findFindingsAtLeast(inv: Investigation, floor: Verdict): Finding[] {
  return Object.values(getAllFindings(inv)).filter((finding) => {
    const result = getFindingResult(inv, finding.key);
    return result?.counted ? isVerdictAtLeast(result.verdict as Verdict, floor) : false;
  });
}

export function findFindingsByRule(inv: Investigation, ruleId: string): Finding[] {
  return Object.values(getAllFindings(inv)).filter((finding) => finding.rule_id === ruleId);
}

export function findFindingsByConfidence(inv: Investigation, band: "low" | "medium" | "high"): Finding[] {
  return Object.values(getAllFindings(inv)).filter((finding) => {
    const result = getFindingResult(inv, finding.key);
    return result ? confidenceBand(result.confidence ?? 1) === band : false;
  });
}

/** Findings excluded from the score but still worth showing, with their reason. */
export function findUncountedFindings(inv: Investigation): Finding[] {
  return Object.values(getAllFindings(inv)).filter((finding) => getFindingResult(inv, finding.key)?.counted === false);
}

/** Findings whose own claim was outweighed by one of their observables — worth surfacing. */
export function findContradictedFindings(inv: Investigation): Finding[] {
  return Object.values(getAllFindings(inv)).filter(
    (finding) => getFindingResult(inv, finding.key)?.own_term_suppressed === true,
  );
}

// --- signals

export function findThreatIntelBySource(inv: Investigation, source: string): ThreatIntel[] {
  return Object.values(getAllThreatIntels(inv)).filter((signal) => signal.source.name === source);
}

export function findThreatIntelByVerdict(inv: Investigation, verdict: Verdict): ThreatIntel[] {
  return Object.values(getAllThreatIntels(inv)).filter((signal) => signal.verdict === verdict);
}

export function findThreatIntelForObservable(inv: Investigation, observableKey: string): ThreatIntel[] {
  return Object.values(getAllThreatIntels(inv)).filter((signal) => signal.subject_key === observableKey);
}
