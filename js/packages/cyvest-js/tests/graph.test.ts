import { describe, it, expect, beforeEach } from "vitest";
import type { CyvestInvestigation } from "../src";
import {
  getRelatedObservables,
  getObservableChildren,
  getObservableParents,
  getRelatedObservablesByType,
  getObservableGraph,
  findSourceObservables,
  findOrphanObservables,
  findLeafObservables,
  areConnected,
  findPath,
  getReachableObservables,
  getAllRelationshipTypes,
  countRelationshipsByType,
  getRelationshipsForObservable,
} from "../src";

// Test fixture with relationships
function createGraphTestInvestigation(): CyvestInvestigation {
  return {
    investigation_id: "01HXYZGRAPHINVESTIGATION",
    investigation_name: "Graph Test Investigation",
    score: 5,
    score_display: "5.00",
    level: "MALICIOUS",
    whitelisted: false,
    whitelists: [],
    observables: {
      "obs:file:msg1": {
        key: "obs:file:msg1",
        type: "file",
        value: "msg1",
        internal: false,
        whitelisted: false,
        comment: "",
        extra: {},
        score: 0,
        score_display: "0.00",
        level: "INFO",
        relationships: [
          {
            target_key: "obs:email:sender@example.com",
            relationship_type: "from",
            direction: "outbound",
          },
          {
            target_key: "obs:ipv4:192.168.1.1",
            relationship_type: "originated-from",
            direction: "outbound",
          },
        ],
        threat_intels: [],
        finding_links: [],
      },
      "obs:email:sender@example.com": {
        key: "obs:email:sender@example.com",
        type: "email",
        value: "sender@example.com",
        internal: false,
        whitelisted: false,
        comment: "",
        extra: {},
        score: 0,
        score_display: "0.00",
        level: "INFO",
        relationships: [
          {
            target_key: "obs:domain:example.com",
            relationship_type: "related-to",
            direction: "outbound",
          },
        ],
        threat_intels: [],
        finding_links: [],
      },
      "obs:ipv4:192.168.1.1": {
        key: "obs:ipv4:192.168.1.1",
        type: "ipv4",
        value: "192.168.1.1",
        internal: true,
        whitelisted: false,
        comment: "",
        extra: {},
        score: 0,
        score_display: "0.00",
        level: "INFO",
        relationships: [],
        threat_intels: [],
        finding_links: [],
      },
      "obs:domain:example.com": {
        key: "obs:domain:example.com",
        type: "domain",
        value: "example.com",
        internal: false,
        whitelisted: false,
        comment: "",
        extra: {},
        score: 5,
        score_display: "5.00",
        level: "MALICIOUS",
        relationships: [],
        threat_intels: [],
        finding_links: [],
      },
      "obs:hash:abc123": {
        key: "obs:hash:abc123",
        type: "hash",
        value: "abc123",
        internal: false,
        whitelisted: false,
        comment: "",
        extra: {},
        score: 3,
        score_display: "3.00",
        level: "SUSPICIOUS",
        relationships: [],
        threat_intels: [],
        finding_links: [],
      },
    },
    findings: {},
    evidences: {},
    threat_intels: {},
    enrichments: {},
    tags: {},
    stats: {
      total_observables: 5,
      internal_observables: 1,
      external_observables: 4,
      whitelisted_observables: 0,
      observables_by_type: {},
      observables_by_level: {},
      observables_by_type_and_level: {},
      total_findings: 0,
      applied_findings: 0,
      findings_by_level: {},
      total_evidences: 0,
      total_threat_intel: 0,
      threat_intel_by_source: {},
      threat_intel_by_level: {},
      total_tags: 0,
    },
    data_extraction: {
      root_type: "file",
      score_mode_obs: "max",
    },
  };
}

describe("Graph Traversal", () => {
  let inv: CyvestInvestigation;

  beforeEach(() => {
    inv = createGraphTestInvestigation();
  });

  describe("getRelatedObservables", () => {
    it("returns all directly connected observables", () => {
      const related = getRelatedObservables(inv, "obs:file:msg1");
      expect(related).toHaveLength(2);
      const values = related.map((o) => o.value);
      expect(values).toContain("sender@example.com");
      expect(values).toContain("192.168.1.1");
    });

    it("returns empty array for non-existent observable", () => {
      expect(getRelatedObservables(inv, "obs:missing:key")).toEqual([]);
    });

    it("includes inbound relationships", () => {
      const related = getRelatedObservables(
        inv,
        "obs:email:sender@example.com"
      );
      // Has outbound to domain and inbound from email message
      expect(related.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe("getObservableChildren", () => {
    it("returns outbound related observables", () => {
      const children = getObservableChildren(inv, "obs:file:msg1");
      expect(children).toHaveLength(2);
    });

    it("returns empty for leaf nodes", () => {
      const children = getObservableChildren(inv, "obs:ipv4:192.168.1.1");
      expect(children).toHaveLength(0);
    });
  });

  describe("getObservableParents", () => {
    it("returns observables pointing to this one", () => {
      const parents = getObservableParents(
        inv,
        "obs:email:sender@example.com"
      );
      expect(parents).toHaveLength(1);
      expect(parents[0].value).toBe("msg1");
    });

    it("returns empty for root nodes", () => {
      const parents = getObservableParents(inv, "obs:file:msg1");
      expect(parents).toHaveLength(0);
    });
  });

  describe("getRelatedObservablesByType", () => {
    it("filters by relationship type", () => {
      const fromRelated = getRelatedObservablesByType(
        inv,
        "obs:file:msg1",
        "from"
      );
      expect(fromRelated).toHaveLength(1);
      expect(fromRelated[0].value).toBe("sender@example.com");
    });
  });

describe("getObservableGraph", () => {
    it("returns correct node count", () => {
      const graph = getObservableGraph(inv);
      expect(graph.nodes).toHaveLength(5);
    });

    it("returns correct edge count", () => {
      const graph = getObservableGraph(inv);
      expect(graph.edges).toHaveLength(3);
    });

    it("nodes have correct structure", () => {
      const graph = getObservableGraph(inv);
      const emailNode = graph.nodes.find(
        (n) => n.id === "obs:file:msg1"
      );
      expect(emailNode).toBeDefined();
      expect(emailNode?.type).toBe("file");
      expect(emailNode?.value).toBe("msg1");
      expect(emailNode?.level).toBe("INFO");
    });

    it("edges have correct structure", () => {
      const graph = getObservableGraph(inv);
      const fromEdge = graph.edges.find((e) => e.type === "from");
      expect(fromEdge).toBeDefined();
      expect(fromEdge?.source).toBe("obs:file:msg1");
      expect(fromEdge?.target).toBe("obs:email:sender@example.com");
    });

    it("preserves distinct semantic relationships between the same nodes", () => {
      inv.observables["obs:file:msg1"].relationships.push({
        target_key: "obs:email:sender@example.com",
        relationship_type: "extraction",
        direction: "outbound",
      });

      const graph = getObservableGraph(inv);
      const parallelEdges = graph.edges.filter(
        (edge) =>
          edge.source === "obs:file:msg1" &&
          edge.target === "obs:email:sender@example.com"
      );

      expect(parallelEdges.map((edge) => edge.type).sort()).toEqual([
        "extraction",
        "from",
      ]);
    });
  });

  describe("findSourceObservables", () => {
    it("finds observables with no incoming relationships", () => {
      const sources = findSourceObservables(inv);
      // file and hash are sources
      expect(sources.length).toBeGreaterThanOrEqual(2);
      const values = sources.map((o) => o.value);
      expect(values).toContain("msg1");
      expect(values).toContain("abc123");
    });
  });

  describe("findOrphanObservables", () => {
    it("finds observables with no relationships", () => {
      const orphans = findOrphanObservables(inv);
      // hash has no relationships
      expect(orphans).toHaveLength(1);
      expect(orphans[0].value).toBe("abc123");
    });
  });

  describe("findLeafObservables", () => {
    it("finds observables that are targets but have no outbound", () => {
      const leaves = findLeafObservables(inv);
      const values = leaves.map((o) => o.value);
      expect(values).toContain("192.168.1.1");
      expect(values).toContain("example.com");
    });
  });

  describe("areConnected", () => {
    it("returns true for directly connected", () => {
      expect(
        areConnected(inv, "obs:file:msg1", "obs:ipv4:192.168.1.1")
      ).toBe(true);
    });

    it("returns true for transitively connected", () => {
      expect(
        areConnected(
          inv,
          "obs:file:msg1",
          "obs:domain:example.com"
        )
      ).toBe(true);
    });

    it("returns false for disconnected", () => {
      expect(
        areConnected(inv, "obs:hash:abc123", "obs:file:msg1")
      ).toBe(false);
    });

    it("returns true for same node", () => {
      expect(
        areConnected(inv, "obs:file:msg1", "obs:file:msg1")
      ).toBe(true);
    });
  });

  describe("findPath", () => {
    it("finds direct path", () => {
      const path = findPath(
        inv,
        "obs:file:msg1",
        "obs:ipv4:192.168.1.1"
      );
      expect(path).toEqual([
        "obs:file:msg1",
        "obs:ipv4:192.168.1.1",
      ]);
    });

    it("finds transitive path", () => {
      const path = findPath(
        inv,
        "obs:file:msg1",
        "obs:domain:example.com"
      );
      expect(path).not.toBeNull();
      expect(path?.length).toBe(3);
      expect(path?.[0]).toBe("obs:file:msg1");
      expect(path?.[path.length - 1]).toBe("obs:domain:example.com");
    });

    it("returns null for no path", () => {
      const path = findPath(
        inv,
        "obs:hash:abc123",
        "obs:file:msg1"
      );
      expect(path).toBeNull();
    });

    it("returns single node for same source/target", () => {
      const path = findPath(
        inv,
        "obs:file:msg1",
        "obs:file:msg1"
      );
      expect(path).toEqual(["obs:file:msg1"]);
    });
  });

  describe("getReachableObservables", () => {
    it("returns all reachable from start", () => {
      const reachable = getReachableObservables(inv, "obs:file:msg1");
      expect(reachable).toHaveLength(4); // msg1 + sender + ip + domain
    });

    it("respects max depth", () => {
      const reachable = getReachableObservables(
        inv,
        "obs:file:msg1",
        1
      );
      expect(reachable).toHaveLength(3); // msg1 + sender + ip (depth 1)
    });
  });

  describe("getAllRelationshipTypes", () => {
    it("returns unique relationship types", () => {
      const types = getAllRelationshipTypes(inv);
      expect(types).toContain("from");
      expect(types).toContain("originated-from");
      expect(types).toContain("related-to");
    });
  });

  describe("countRelationshipsByType", () => {
    it("counts relationships by type", () => {
      const counts = countRelationshipsByType(inv);
      expect(counts["from"]).toBe(1);
      expect(counts["originated-from"]).toBe(1);
      expect(counts["related-to"]).toBe(1);
    });
  });

  describe("getRelationshipsForObservable", () => {
    it("returns outbound and inbound relationships", () => {
      const rels = getRelationshipsForObservable(
        inv,
        "obs:email:sender@example.com"
      );
      expect(rels.outbound).toHaveLength(1);
      expect(rels.inbound).toHaveLength(1);
      expect(rels.all.length).toBe(2);
    });
  });
});
