/**
 * Graph and relationship traversal utilities for Cyvest Investigation.
 *
 * These functions provide graph-like traversal of observable relationships,
 * useful for understanding connections and preparing data for visualization.
 */

import type {
  CyvestInvestigation,
  Observable,
  Relationship,
  Level,
  RelationshipDirection,
} from "./types.generated";

/**
 * Edge representation for graph operations.
 */
export interface GraphEdge {
  /** Source observable key */
  source: string;
  /** Target observable key */
  target: string;
  /** Relationship type label */
  type: string;
  /** Relationship direction */
  direction: RelationshipDirection;
}

/**
 * Graph node representation.
 */
export interface GraphNode {
  /** Observable key (unique identifier) */
  id: string;
  /** Observable type */
  type: string;
  /** Observable value */
  value: string;
  /** Security level */
  level: Level;
  /** Numeric score */
  score: number;
  /** Whether internal */
  internal: boolean;
  /** Whether whitelisted */
  whitelisted: boolean;
}

/**
 * Full graph representation of an investigation.
 */
export interface InvestigationGraph {
  /** All nodes (observables) */
  nodes: GraphNode[];
  /** All edges (relationships) */
  edges: GraphEdge[];
}

// ============================================================================
// Relationship Traversal
// ============================================================================

/**
 * Get all related observables for a given observable.
 *
 * Returns observables that are directly connected via any relationship,
 * regardless of direction.
 *
 * @param inv - The investigation to search
 * @param observableKey - Key of the source observable
 * @returns Array of related observables
 *
 * @example
 * ```ts
 * const related = getRelatedObservables(investigation, "obs:email:test@example.com");
 * ```
 */
export function getRelatedObservables(
  inv: CyvestInvestigation,
  observableKey: string
): Observable[] {
  const observable = inv.observables[observableKey];
  if (!observable) {
    return [];
  }

  const relatedKeys = new Set<string>();

  // Get outbound relationships from this observable
  for (const rel of observable.relationships) {
    relatedKeys.add(rel.target_key);
  }

  // Get inbound relationships (observables pointing to this one)
  for (const [key, obs] of Object.entries(inv.observables)) {
    if (key === observableKey) continue;
    for (const rel of obs.relationships) {
      if (rel.target_key === observableKey) {
        relatedKeys.add(key);
        break;
      }
    }
  }

  // Resolve keys to observables
  return Array.from(relatedKeys)
    .map((key) => inv.observables[key])
    .filter((obs): obs is Observable => obs !== undefined);
}

/**
 * Get observables related by outbound relationships (children).
 *
 * @param inv - The investigation to search
 * @param observableKey - Key of the source observable
 * @returns Array of child observables
 */
export function getObservableChildren(
  inv: CyvestInvestigation,
  observableKey: string
): Observable[] {
  const observable = inv.observables[observableKey];
  if (!observable) {
    return [];
  }

  return observable.relationships
    .filter((rel) => rel.direction === "outbound" || rel.direction === "bidirectional")
    .map((rel) => inv.observables[rel.target_key])
    .filter((obs): obs is Observable => obs !== undefined);
}

/**
 * Get observables related by inbound relationships (parents).
 *
 * @param inv - The investigation to search
 * @param observableKey - Key of the target observable
 * @returns Array of parent observables
 */
export function getObservableParents(
  inv: CyvestInvestigation,
  observableKey: string
): Observable[] {
  const parents: Observable[] = [];

  for (const [key, obs] of Object.entries(inv.observables)) {
    if (key === observableKey) continue;

    for (const rel of obs.relationships) {
      if (
        rel.target_key === observableKey &&
        (rel.direction === "outbound" || rel.direction === "bidirectional")
      ) {
        parents.push(obs);
        break;
      }
    }
  }

  return parents;
}

/**
 * Get related observables filtered by relationship type.
 *
 * @param inv - The investigation to search
 * @param observableKey - Key of the source observable
 * @param relationshipType - Type of relationship to filter (e.g., "related-to", "extraction")
 * @returns Array of related observables
 */
export function getRelatedObservablesByType(
  inv: CyvestInvestigation,
  observableKey: string,
  relationshipType: string
): Observable[] {
  const observable = inv.observables[observableKey];
  if (!observable) {
    return [];
  }

  const normalizedType = relationshipType.toLowerCase();
  const relatedKeys = new Set<string>();

  // Outbound with matching type
  for (const rel of observable.relationships) {
    if (rel.relationship_type.toLowerCase() === normalizedType) {
      relatedKeys.add(rel.target_key);
    }
  }

  // Inbound with matching type
  for (const [key, obs] of Object.entries(inv.observables)) {
    if (key === observableKey) continue;
    for (const rel of obs.relationships) {
      if (
        rel.target_key === observableKey &&
        rel.relationship_type.toLowerCase() === normalizedType
      ) {
        relatedKeys.add(key);
        break;
      }
    }
  }

  return Array.from(relatedKeys)
    .map((key) => inv.observables[key])
    .filter((obs): obs is Observable => obs !== undefined);
}

/**
 * Get related observables filtered by direction.
 *
 * @param inv - The investigation to search
 * @param observableKey - Key of the source observable
 * @param direction - Direction to filter by
 * @returns Array of related observables
 */
export function getRelatedObservablesByDirection(
  inv: CyvestInvestigation,
  observableKey: string,
  direction: RelationshipDirection
): Observable[] {
  const observable = inv.observables[observableKey];
  if (!observable) {
    return [];
  }

  const relatedKeys = new Set<string>();

  if (direction === "outbound" || direction === "bidirectional") {
    for (const rel of observable.relationships) {
      if (rel.direction === direction || rel.direction === "bidirectional") {
        relatedKeys.add(rel.target_key);
      }
    }
  }

  if (direction === "inbound" || direction === "bidirectional") {
    for (const [key, obs] of Object.entries(inv.observables)) {
      if (key === observableKey) continue;
      for (const rel of obs.relationships) {
        if (
          rel.target_key === observableKey &&
          (rel.direction === "outbound" || rel.direction === "bidirectional")
        ) {
          relatedKeys.add(key);
          break;
        }
      }
    }
  }

  return Array.from(relatedKeys)
    .map((key) => inv.observables[key])
    .filter((obs): obs is Observable => obs !== undefined);
}

// ============================================================================
// Graph Construction
// ============================================================================

/**
 * Build a graph representation of all observables and their relationships.
 *
 * Useful for visualization libraries like vis.js, d3, or cytoscape.
 *
 * @param inv - The investigation
 * @returns Graph with nodes and edges
 *
 * @example
 * ```ts
 * const graph = getObservableGraph(investigation);
 * console.log(`Nodes: ${graph.nodes.length}, Edges: ${graph.edges.length}`);
 *
 * // Use with vis.js:
 * const network = new vis.Network(container, {
 *   nodes: graph.nodes.map(n => ({ id: n.id, label: n.value })),
 *   edges: graph.edges.map(e => ({ from: e.source, to: e.target, label: e.type }))
 * });
 * ```
 */
export function getObservableGraph(inv: CyvestInvestigation): InvestigationGraph {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const seenEdges = new Set<string>();

  // Build nodes
  for (const [key, obs] of Object.entries(inv.observables)) {
    nodes.push({
      id: key,
      type: obs.type,
      value: obs.value,
      level: obs.level,
      score: obs.score,
      internal: obs.internal,
      whitelisted: obs.whitelisted,
    });

    // Build edges from relationships
    for (const rel of obs.relationships) {
      // Create a unique edge key to avoid duplicates
      const endpoints =
        rel.direction === "bidirectional"
          ? [key, rel.target_key].sort().join("--")
          : `${key}--${rel.target_key}`;
      // Multiple semantic relationships may legitimately connect the same
      // observables. Only collapse an exact duplicate (including its type and
      // direction), while still folding reverse copies of bidirectional links.
      const edgeKey = `${endpoints}--${rel.relationship_type}--${rel.direction}`;

      if (!seenEdges.has(edgeKey)) {
        seenEdges.add(edgeKey);
        edges.push({
          source: key,
          target: rel.target_key,
          type: rel.relationship_type,
          direction: rel.direction,
        });
      }
    }
  }

  return { nodes, edges };
}

// ============================================================================
// Root & Orphan Detection
// ============================================================================

/**
 * Find source observables in the investigation graph.
 *
 * Source observables are those that have no incoming relationships
 * (nothing points to them as a target).
 *
 * @param inv - The investigation
 * @returns Array of source observables
 */
export function findSourceObservables(inv: CyvestInvestigation): Observable[] {
  const targetKeys = new Set<string>();

  // Collect all target keys from relationships
  for (const obs of Object.values(inv.observables)) {
    for (const rel of obs.relationships) {
      if (rel.direction === "outbound" || rel.direction === "bidirectional") {
        targetKeys.add(rel.target_key);
      }
    }
  }

  // Find observables that are never targets
  return Object.values(inv.observables).filter(
    (obs) => !targetKeys.has(obs.key)
  );
}

/**
 * Find orphan observables (not connected to any other observable).
 *
 * @param inv - The investigation
 * @returns Array of orphan observables
 */
export function findOrphanObservables(inv: CyvestInvestigation): Observable[] {
  const connectedKeys = new Set<string>();

  // Mark all observables that have relationships
  for (const obs of Object.values(inv.observables)) {
    if (obs.relationships.length > 0) {
      connectedKeys.add(obs.key);
      for (const rel of obs.relationships) {
        connectedKeys.add(rel.target_key);
      }
    }
  }

  // Return observables not in the connected set
  return Object.values(inv.observables).filter(
    (obs) => !connectedKeys.has(obs.key)
  );
}

/**
 * Find leaf observables (have incoming but no outgoing relationships).
 *
 * @param inv - The investigation
 * @returns Array of leaf observables
 */
export function findLeafObservables(inv: CyvestInvestigation): Observable[] {
  const hasOutbound = new Set<string>();
  const isTarget = new Set<string>();

  for (const obs of Object.values(inv.observables)) {
    for (const rel of obs.relationships) {
      if (rel.direction === "outbound" || rel.direction === "bidirectional") {
        hasOutbound.add(obs.key);
        isTarget.add(rel.target_key);
      }
    }
  }

  // Leaves are targets that have no outbound relationships
  return Object.values(inv.observables).filter(
    (obs) => isTarget.has(obs.key) && !hasOutbound.has(obs.key)
  );
}

// ============================================================================
// Path Finding
// ============================================================================

/**
 * Check if two observables are connected (directly or transitively).
 *
 * @param inv - The investigation
 * @param sourceKey - Starting observable key
 * @param targetKey - Target observable key
 * @returns True if a path exists from source to target
 */
export function areConnected(
  inv: CyvestInvestigation,
  sourceKey: string,
  targetKey: string
): boolean {
  if (sourceKey === targetKey) return true;

  const visited = new Set<string>();
  const queue = [sourceKey];

  while (queue.length > 0) {
    const current = queue.shift()!;
    if (visited.has(current)) continue;
    visited.add(current);

    const obs = inv.observables[current];
    if (!obs) continue;

    for (const rel of obs.relationships) {
      if (rel.target_key === targetKey) {
        return true;
      }
      if (!visited.has(rel.target_key)) {
        queue.push(rel.target_key);
      }
    }
  }

  return false;
}

/**
 * Find the shortest path between two observables.
 *
 * @param inv - The investigation
 * @param sourceKey - Starting observable key
 * @param targetKey - Target observable key
 * @returns Array of observable keys representing the path, or null if no path exists
 */
export function findPath(
  inv: CyvestInvestigation,
  sourceKey: string,
  targetKey: string
): string[] | null {
  if (sourceKey === targetKey) return [sourceKey];

  const visited = new Set<string>();
  const queue: { key: string; path: string[] }[] = [
    { key: sourceKey, path: [sourceKey] },
  ];

  while (queue.length > 0) {
    const { key: current, path } = queue.shift()!;
    if (visited.has(current)) continue;
    visited.add(current);

    const obs = inv.observables[current];
    if (!obs) continue;

    for (const rel of obs.relationships) {
      if (rel.target_key === targetKey) {
        return [...path, targetKey];
      }
      if (!visited.has(rel.target_key)) {
        queue.push({ key: rel.target_key, path: [...path, rel.target_key] });
      }
    }
  }

  return null;
}

/**
 * Get all observables reachable from a starting point.
 *
 * @param inv - The investigation
 * @param startKey - Starting observable key
 * @param maxDepth - Maximum traversal depth (default: Infinity)
 * @returns Array of reachable observables
 */
export function getReachableObservables(
  inv: CyvestInvestigation,
  startKey: string,
  maxDepth = Infinity
): Observable[] {
  const visited = new Set<string>();
  const result: Observable[] = [];

  function traverse(key: string, depth: number): void {
    if (depth > maxDepth || visited.has(key)) return;
    visited.add(key);

    const obs = inv.observables[key];
    if (!obs) return;

    result.push(obs);

    for (const rel of obs.relationships) {
      traverse(rel.target_key, depth + 1);
    }
  }

  traverse(startKey, 0);
  return result;
}

// ============================================================================
// Relationship Type Utilities
// ============================================================================

/**
 * Get all unique relationship types used in the investigation.
 *
 * @param inv - The investigation
 * @returns Array of unique relationship type strings
 */
export function getAllRelationshipTypes(inv: CyvestInvestigation): string[] {
  const types = new Set<string>();

  for (const obs of Object.values(inv.observables)) {
    for (const rel of obs.relationships) {
      types.add(rel.relationship_type);
    }
  }

  return Array.from(types);
}

/**
 * Count relationships by type.
 *
 * @param inv - The investigation
 * @returns Object mapping relationship type to count
 */
export function countRelationshipsByType(
  inv: CyvestInvestigation
): Record<string, number> {
  const counts: Record<string, number> = {};

  for (const obs of Object.values(inv.observables)) {
    for (const rel of obs.relationships) {
      counts[rel.relationship_type] = (counts[rel.relationship_type] || 0) + 1;
    }
  }

  return counts;
}

/**
 * Get all relationships for an observable.
 *
 * @param inv - The investigation
 * @param observableKey - Observable key
 * @returns Object with outbound, inbound, and all relationships
 */
export function getRelationshipsForObservable(
  inv: CyvestInvestigation,
  observableKey: string
): {
  outbound: Relationship[];
  inbound: Array<Relationship & { source_key: string }>;
  all: Array<Relationship & { source_key?: string }>;
} {
  const observable = inv.observables[observableKey];
  const outbound: Relationship[] = observable?.relationships || [];

  const inbound: Array<Relationship & { source_key: string }> = [];

  for (const [key, obs] of Object.entries(inv.observables)) {
    if (key === observableKey) continue;
    for (const rel of obs.relationships) {
      if (rel.target_key === observableKey) {
        inbound.push({ ...rel, source_key: key });
      }
    }
  }

  return {
    outbound,
    inbound,
    all: [
      ...outbound,
      ...inbound,
    ],
  };
}
