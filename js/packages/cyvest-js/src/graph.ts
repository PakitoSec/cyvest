/**
 * Graph traversal.
 *
 * Relations are standalone facts in v7, each carrying both keys, so there is no per-observable
 * adjacency list to walk and no `direction` field to interpret: `source_key` is the parent,
 * `target_key` the child, and the kind implies the rest.
 */

import { getAllObservables, getAllRelations, getObservableResult } from "./getters";
import type { Investigation, Observable, Relation } from "./types";

export interface GraphEdge {
  key: string;
  source: string;
  target: string;
  kind: string;
  confidence: number;
  /** True when the edge actually carried score, per the report's contributions. */
  carriedScore: boolean;
}

export interface GraphNode {
  key: string;
  observable: Observable;
  score: number;
  verdict: string;
}

export interface InvestigationGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

function relationsOf(inv: Investigation): Relation[] {
  return Object.values(getAllRelations(inv));
}

/** Keys of relations the report credits with an actual contribution. */
function scoringRelationKeys(inv: Investigation): Set<string> {
  const keys = new Set<string>();
  for (const result of Object.values(inv.report.observables ?? {})) {
    for (const contribution of result.contributions ?? []) {
      if (contribution.retained !== false && contribution.source_key.startsWith("rel:")) {
        keys.add(contribution.source_key);
      }
    }
  }
  return keys;
}

export function getObservableChildren(inv: Investigation, observableKey: string): Observable[] {
  const observables = getAllObservables(inv);
  return relationsOf(inv)
    .filter((relation) => relation.source_key === observableKey)
    .map((relation) => observables[relation.target_key])
    .filter((observable): observable is Observable => observable !== undefined);
}

export function getObservableParents(inv: Investigation, observableKey: string): Observable[] {
  const observables = getAllObservables(inv);
  return relationsOf(inv)
    .filter((relation) => relation.target_key === observableKey)
    .map((relation) => observables[relation.source_key])
    .filter((observable): observable is Observable => observable !== undefined);
}

export function getRelatedObservables(inv: Investigation, observableKey: string): Observable[] {
  const seen = new Map<string, Observable>();
  for (const observable of [
    ...getObservableChildren(inv, observableKey),
    ...getObservableParents(inv, observableKey),
  ]) {
    seen.set(observable.key, observable);
  }
  return [...seen.values()];
}

export function getRelationsForObservable(inv: Investigation, observableKey: string): Relation[] {
  return relationsOf(inv).filter(
    (relation) => relation.source_key === observableKey || relation.target_key === observableKey,
  );
}

export function countRelationsByKind(inv: Investigation): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const relation of relationsOf(inv)) {
    counts[relation.kind ?? "related-to"] = (counts[relation.kind ?? "related-to"] ?? 0) + 1;
  }
  return counts;
}

export function getObservableGraph(inv: Investigation): InvestigationGraph {
  const scoring = scoringRelationKeys(inv);
  return {
    nodes: Object.values(getAllObservables(inv)).map((observable) => {
      const result = getObservableResult(inv, observable.key);
      return {
        key: observable.key,
        observable,
        score: result?.score ?? 0,
        verdict: result?.verdict ?? "INFO",
      };
    }),
    edges: relationsOf(inv).map((relation) => ({
      key: relation.key,
      source: relation.source_key,
      target: relation.target_key,
      kind: relation.kind ?? "related-to",
      confidence: relation.confidence ?? 1,
      carriedScore: scoring.has(relation.key),
    })),
  };
}

export function areConnected(inv: Investigation, a: string, b: string): boolean {
  return getReachableObservables(inv, a).has(b);
}

/** Undirected reachability — the same walk `finalize_relationships` uses to spot orphans. */
export function getReachableObservables(inv: Investigation, start: string): Set<string> {
  const relations = relationsOf(inv);
  const reached = new Set([start]);
  const queue = [start];

  while (queue.length > 0) {
    const current = queue.shift() as string;
    for (const relation of relations) {
      const neighbour =
        relation.source_key === current ? relation.target_key : relation.target_key === current ? relation.source_key : undefined;
      if (neighbour && !reached.has(neighbour)) {
        reached.add(neighbour);
        queue.push(neighbour);
      }
    }
  }
  return reached;
}

export function findOrphanObservables(inv: Investigation): Observable[] {
  const linked = new Set<string>();
  for (const relation of relationsOf(inv)) {
    linked.add(relation.source_key);
    linked.add(relation.target_key);
  }
  return Object.values(getAllObservables(inv)).filter((observable) => !linked.has(observable.key));
}

export function findLeafObservables(inv: Investigation): Observable[] {
  const parents = new Set(relationsOf(inv).map((relation) => relation.source_key));
  return Object.values(getAllObservables(inv)).filter((observable) => !parents.has(observable.key));
}

export function findSourceObservables(inv: Investigation): Observable[] {
  const children = new Set(relationsOf(inv).map((relation) => relation.target_key));
  return Object.values(getAllObservables(inv)).filter((observable) => !children.has(observable.key));
}
