import { describe, it, expect, beforeEach } from "vitest";
import type { CyvestInvestigation } from "../src";
import {
  // Getters
  getObservable,
  getObservableByTypeValue,
  getCheck,
  getCheckByName,
  getAllChecks,
  getThreatIntel,
  getThreatIntelBySourceObservable,
  getAllThreatIntels,
  getEnrichment,
  getEnrichmentByName,
  getAllEnrichments,
  getTag,
  getTagByName,
  getAllTags,
  getAllObservables,
  getCounts,
  getStartedAt,
  getTagChildren,
  getTagDescendants,
  getTagAggregatedScore,
  getTagAggregatedLevel,
  // Finders
  findObservablesByType,
  findObservablesByLevel,
  findObservablesAtLeast,
  findObservablesByValue,
  findInternalObservables,
  findWhitelistedObservables,
  findChecksByLevel,
  findChecksAtLeast,
  findThreatIntelBySource,
  findChecksForObservable,
  findThreatIntelsForObservable,
  findObservablesForCheck,
  findHighestScoringObservables,
  findMaliciousObservables,
  getAllCheckKeys,
  getAllObservableTypes,
} from "../src";

// Test fixture
function createTestInvestigation(): CyvestInvestigation {
  return {
    investigation_id: "01HXYZTESTINVESTIGATION",
    investigation_name: "Test Investigation",
    score: 7.5,
    score_display: "7.50",
    level: "MALICIOUS",
    whitelisted: false,
    audit_log: [
      {
        event_id: "01HXYZTESTEVENT001",
        timestamp: "2024-01-01T00:00:00Z",
        event_type: "INVESTIGATION_STARTED",
        object_type: "investigation",
        object_key: "01HXYZTESTINVESTIGATION",
      },
    ],
    whitelists: [
      {
        identifier: "wl-1",
        name: "Test Whitelist",
        justification: "Testing",
      },
    ],
    observables: {
      "obs:ipv4-addr:192.168.1.1": {
        key: "obs:ipv4-addr:192.168.1.1",
        type: "ipv4-addr",
        value: "192.168.1.1",
        internal: true,
        whitelisted: false,
        comment: "",
        extra: {},
        score: 0,
        score_display: "0.00",
        level: "INFO",
        relationships: [
          {
            target_key: "obs:domain-name:example.com",
            relationship_type: "related-to",
            direction: "outbound",
          },
        ],
        threat_intels: [],
        check_links: ["chk:ip_check:network"],
      },
      "obs:ipv4-addr:8.8.8.8": {
        key: "obs:ipv4-addr:8.8.8.8",
        type: "ipv4-addr",
        value: "8.8.8.8",
        internal: false,
        whitelisted: true,
        comment: "Google DNS",
        extra: {},
        score: -1,
        score_display: "-1.00",
        level: "TRUSTED",
        relationships: [],
        threat_intels: [],
        check_links: [],
      },
      "obs:domain-name:example.com": {
        key: "obs:domain-name:example.com",
        type: "domain-name",
        value: "example.com",
        internal: false,
        whitelisted: false,
        comment: "",
        extra: {},
        score: 5,
        score_display: "5.00",
        level: "MALICIOUS",
        relationships: [],
        threat_intels: ["ti:virustotal:obs:domain-name:example.com"],
        check_links: ["chk:domain_check:dns"],
      },
      "obs:url:http://malware.com/bad": {
        key: "obs:url:http://malware.com/bad",
        type: "url",
        value: "http://malware.com/bad",
        internal: false,
        whitelisted: false,
        comment: "",
        extra: {},
        score: 7.5,
        score_display: "7.50",
        level: "MALICIOUS",
        relationships: [],
        threat_intels: [],
        check_links: [],
      },
    },
    checks: {
      "chk:ip_check": {
        key: "chk:ip_check",
        check_name: "ip_check",
        description: "IP address check",
        comment: "",
        extra: {},
        score: 0,
        score_display: "0.00",
        level: "INFO",
        origin_investigation_id: "01HXYZTESTINVESTIGATION",
        observable_links: [
          {
            observable_key: "obs:ipv4-addr:192.168.1.1",
          },
        ],
      },
      "chk:domain_check": {
        key: "chk:domain_check",
        check_name: "domain_check",
        description: "Domain reputation check",
        comment: "",
        extra: {},
        score: 5,
        score_display: "5.00",
        level: "MALICIOUS",
        origin_investigation_id: "01HXYZTESTINVESTIGATION",
        observable_links: [
          {
            observable_key: "obs:domain-name:example.com",
          },
        ],
      },
      "chk:dns_lookup": {
        key: "chk:dns_lookup",
        check_name: "dns_lookup",
        description: "DNS lookup",
        comment: "",
        extra: {},
        score: 0,
        score_display: "0.00",
        level: "INFO",
        origin_investigation_id: "01HXYZTESTINVESTIGATION",
        observable_links: [],
      },
    },
    threat_intels: {
      "ti:virustotal:obs:domain-name:example.com": {
        key: "ti:virustotal:obs:domain-name:example.com",
        source: "virustotal",
        observable_key: "obs:domain-name:example.com",
        comment: "",
        extra: {},
        score: 5,
        score_display: "5.00",
        level: "MALICIOUS",
        taxonomies: [{ level: "MALICIOUS", name: "verdict", value: "malicious" }],
      },
    },
    enrichments: {
      "enr:whois": {
        key: "enr:whois",
        name: "whois",
        data: { registrar: "Test Registrar" },
        context: "example.com",
      },
    },
    tags: {
      "tag:email": {
        key: "tag:email",
        name: "email",
        description: "Email tag",
        checks: [],
        direct_score: 1.5,
        direct_level: "NOTABLE",
      },
      "tag:email:headers": {
        key: "tag:email:headers",
        name: "email:headers",
        description: "Email headers",
        checks: ["chk:ip_check"],
        direct_score: 2.0,
        direct_level: "NOTABLE",
      },
      "tag:email:headers:auth": {
        key: "tag:email:headers:auth",
        name: "email:headers:auth",
        description: "Auth headers",
        checks: [],
        direct_score: 3.5,
        direct_level: "SUSPICIOUS",
      },
      "tag:email:body": {
        key: "tag:email:body",
        name: "email:body",
        description: "Email body",
        checks: [],
        direct_score: 1.0,
        direct_level: "NOTABLE",
      },
    },
    stats: {
      total_observables: 4,
      internal_observables: 1,
      external_observables: 3,
      whitelisted_observables: 1,
      observables_by_type: { "ipv4-addr": 2, "domain-name": 1, url: 1 },
      observables_by_level: { INFO: 1, TRUSTED: 1, MALICIOUS: 2 },
      observables_by_type_and_level: {},
      total_checks: 3,
      applied_checks: 2,
      checks_by_level: { INFO: ["chk:ip_check", "chk:dns_lookup"], MALICIOUS: ["chk:domain_check"] },
      total_threat_intel: 1,
      threat_intel_by_source: { virustotal: 1 },
      threat_intel_by_level: { MALICIOUS: 1 },
      total_tags: 4,
    },
    data_extraction: {
      root_type: "file",
      score_mode_obs: "max",
    },
  };
}

describe("Getters", () => {
  let inv: CyvestInvestigation;

  beforeEach(() => {
    inv = createTestInvestigation();
  });

  describe("getObservable", () => {
    it("returns observable by key", () => {
      const obs = getObservable(inv, "obs:ipv4-addr:192.168.1.1");
      expect(obs).toBeDefined();
      expect(obs?.value).toBe("192.168.1.1");
    });

    it("returns undefined for missing key", () => {
      expect(getObservable(inv, "obs:missing:key")).toBeUndefined();
    });
  });

  describe("getObservableByTypeValue", () => {
    it("finds observable by type and value", () => {
      const obs = getObservableByTypeValue(inv, "ipv4-addr", "192.168.1.1");
      expect(obs).toBeDefined();
      expect(obs?.key).toBe("obs:ipv4-addr:192.168.1.1");
    });

    it("is case insensitive", () => {
      const obs = getObservableByTypeValue(inv, "IPV4-ADDR", "192.168.1.1");
      expect(obs).toBeDefined();
    });
  });

  describe("getCheck", () => {
    it("returns check by key", () => {
      const check = getCheck(inv, "chk:domain_check");
      expect(check).toBeDefined();
      expect(check?.check_name).toBe("domain_check");
    });
  });

  describe("getCheckByName", () => {
    it("finds check by name", () => {
      const check = getCheckByName(inv, "domain_check");
      expect(check).toBeDefined();
      expect(check?.key).toBe("chk:domain_check");
    });
  });

  describe("getAllChecks", () => {
    it("returns all checks as flat array", () => {
      const checks = getAllChecks(inv);
      expect(checks).toHaveLength(3);
    });
  });

  describe("getThreatIntel", () => {
    it("returns threat intel by key", () => {
      const ti = getThreatIntel(
        inv,
        "ti:virustotal:obs:domain-name:example.com"
      );
      expect(ti).toBeDefined();
      expect(ti?.source).toBe("virustotal");
    });
  });

  describe("getTag", () => {
    it("returns tag by key", () => {
      const tag = getTag(inv, "tag:email");
      expect(tag).toBeDefined();
      expect(tag?.name).toBe("email");
    });

    it("returns nested tag", () => {
      const tag = getTag(inv, "tag:email:headers");
      expect(tag).toBeDefined();
      expect(tag?.name).toBe("email:headers");
    });
  });

  describe("getAllTags", () => {
    it("returns all tags", () => {
      const tags = getAllTags(inv);
      expect(tags).toHaveLength(4);
    });
  });

  describe("getCounts", () => {
    it("returns correct counts", () => {
      const counts = getCounts(inv);
      expect(counts.observables).toBe(4);
      expect(counts.checks).toBe(3);
      expect(counts.threatIntels).toBe(1);
      expect(counts.enrichments).toBe(1);
      expect(counts.tags).toBe(4);
      expect(counts.whitelists).toBe(1);
    });
  });

  describe("getStartedAt", () => {
    it("returns timestamp from INVESTIGATION_STARTED event", () => {
      const startedAt = getStartedAt(inv);
      expect(startedAt).toBe("2024-01-01T00:00:00Z");
    });

    it("returns undefined when no audit_log", () => {
      const invWithoutAuditLog = { ...inv, audit_log: undefined };
      const startedAt = getStartedAt(invWithoutAuditLog);
      expect(startedAt).toBeUndefined();
    });

    it("returns undefined when no INVESTIGATION_STARTED event", () => {
      const invWithEmptyLog = { ...inv, audit_log: [] };
      const startedAt = getStartedAt(invWithEmptyLog);
      expect(startedAt).toBeUndefined();
    });
  });
});

describe("Finders", () => {
  let inv: CyvestInvestigation;

  beforeEach(() => {
    inv = createTestInvestigation();
  });

  describe("findObservablesByType", () => {
    it("finds observables of specific type", () => {
      const ips = findObservablesByType(inv, "ipv4-addr");
      expect(ips).toHaveLength(2);
    });

    it("is case insensitive", () => {
      const ips = findObservablesByType(inv, "IPV4-ADDR");
      expect(ips).toHaveLength(2);
    });
  });

  describe("findObservablesByLevel", () => {
    it("finds observables at specific level", () => {
      const malicious = findObservablesByLevel(inv, "MALICIOUS");
      expect(malicious).toHaveLength(2);
    });
  });

  describe("findObservablesAtLeast", () => {
    it("finds observables at or above level", () => {
      const suspicious = findObservablesAtLeast(inv, "SUSPICIOUS");
      expect(suspicious).toHaveLength(2); // 2 malicious
    });
  });

  describe("findInternalObservables", () => {
    it("finds internal observables", () => {
      const internal = findInternalObservables(inv);
      expect(internal).toHaveLength(1);
      expect(internal[0].internal).toBe(true);
    });
  });

  describe("findWhitelistedObservables", () => {
    it("finds whitelisted observables", () => {
      const whitelisted = findWhitelistedObservables(inv);
      expect(whitelisted).toHaveLength(1);
      expect(whitelisted[0].value).toBe("8.8.8.8");
    });
  });

  describe("findChecksByLevel", () => {
    it("finds checks at level", () => {
      const malicious = findChecksByLevel(inv, "MALICIOUS");
      expect(malicious).toHaveLength(1);
    });
  });

  describe("findThreatIntelBySource", () => {
    it("finds threat intel from source", () => {
      const vt = findThreatIntelBySource(inv, "virustotal");
      expect(vt).toHaveLength(1);
    });
  });

  describe("findChecksForObservable", () => {
    it("finds checks that reference observable", () => {
      const checks = findChecksForObservable(inv, "obs:ipv4-addr:192.168.1.1");
      expect(checks).toHaveLength(1);
      expect(checks[0].check_name).toBe("ip_check");
    });
  });

  describe("findThreatIntelsForObservable", () => {
    it("finds threat intel for observable", () => {
      const tis = findThreatIntelsForObservable(
        inv,
        "obs:domain-name:example.com"
      );
      expect(tis).toHaveLength(1);
      expect(tis[0].source).toBe("virustotal");
    });
  });

  describe("findObservablesForCheck", () => {
    it("finds observables referenced by check", () => {
      const obs = findObservablesForCheck(inv, "chk:ip_check");
      expect(obs).toHaveLength(1);
      expect(obs[0].value).toBe("192.168.1.1");
    });
  });

  describe("findHighestScoringObservables", () => {
    it("returns top scoring observables", () => {
      const top = findHighestScoringObservables(inv, 2);
      expect(top).toHaveLength(2);
      expect(top[0].score).toBeGreaterThanOrEqual(top[1].score);
    });
  });

  describe("findMaliciousObservables", () => {
    it("returns malicious observables", () => {
      const mal = findMaliciousObservables(inv);
      expect(mal).toHaveLength(2);
    });
  });

  describe("getAllCheckKeys", () => {
    it("returns all check keys", () => {
      const keys = getAllCheckKeys(inv);
      expect(keys).toContain("chk:ip_check");
      expect(keys).toContain("chk:domain_check");
    });
  });

  describe("getAllObservableTypes", () => {
    it("returns all observable types", () => {
      const types = getAllObservableTypes(inv);
      expect(types).toContain("ipv4-addr");
      expect(types).toContain("domain-name");
      expect(types).toContain("url");
    });
  });

  // Tag Aggregation Tests
  describe("getTagChildren", () => {
    it("returns direct children of a tag", () => {
      const children = getTagChildren(inv, "email");
      expect(children).toHaveLength(2);
      const names = children.map((t) => t.name);
      expect(names).toContain("email:headers");
      expect(names).toContain("email:body");
    });

    it("does not return grandchildren", () => {
      const children = getTagChildren(inv, "email");
      const names = children.map((t) => t.name);
      expect(names).not.toContain("email:headers:auth");
    });

    it("returns empty array for leaf tag", () => {
      const children = getTagChildren(inv, "email:headers:auth");
      expect(children).toHaveLength(0);
    });

    it("returns empty array for non-existent tag", () => {
      const children = getTagChildren(inv, "nonexistent");
      expect(children).toHaveLength(0);
    });
  });

  describe("getTagDescendants", () => {
    it("returns all descendants of a tag", () => {
      const descendants = getTagDescendants(inv, "email");
      expect(descendants).toHaveLength(3);
      const names = descendants.map((t) => t.name);
      expect(names).toContain("email:headers");
      expect(names).toContain("email:headers:auth");
      expect(names).toContain("email:body");
    });

    it("returns children and grandchildren", () => {
      const descendants = getTagDescendants(inv, "email:headers");
      expect(descendants).toHaveLength(1);
      expect(descendants[0].name).toBe("email:headers:auth");
    });

    it("returns empty array for leaf tag", () => {
      const descendants = getTagDescendants(inv, "email:headers:auth");
      expect(descendants).toHaveLength(0);
    });
  });

  describe("getTagAggregatedScore", () => {
    it("returns aggregated score including all descendants", () => {
      // email (1.5) + email:headers (2.0) + email:headers:auth (3.5) + email:body (1.0) = 8.0
      const score = getTagAggregatedScore(inv, "email");
      expect(score).toBe(8.0);
    });

    it("returns aggregated score for intermediate tag", () => {
      // email:headers (2.0) + email:headers:auth (3.5) = 5.5
      const score = getTagAggregatedScore(inv, "email:headers");
      expect(score).toBe(5.5);
    });

    it("returns direct score for leaf tag", () => {
      const score = getTagAggregatedScore(inv, "email:headers:auth");
      expect(score).toBe(3.5);
    });

    it("returns 0 for non-existent tag", () => {
      const score = getTagAggregatedScore(inv, "nonexistent");
      expect(score).toBe(0);
    });
  });

  describe("getTagAggregatedLevel", () => {
    it("returns level based on aggregated score", () => {
      // email aggregated score = 8.0 -> MALICIOUS (>= 5)
      const level = getTagAggregatedLevel(inv, "email");
      expect(level).toBe("MALICIOUS");
    });

    it("returns level for intermediate tag", () => {
      // email:headers aggregated score = 5.5 -> MALICIOUS (>= 5)
      const level = getTagAggregatedLevel(inv, "email:headers");
      expect(level).toBe("MALICIOUS");
    });

    it("returns level for leaf tag", () => {
      // email:headers:auth direct score = 3.5 -> SUSPICIOUS (3 <= x < 5)
      const level = getTagAggregatedLevel(inv, "email:headers:auth");
      expect(level).toBe("SUSPICIOUS");
    });

    it("returns INFO for non-existent tag (score 0)", () => {
      const level = getTagAggregatedLevel(inv, "nonexistent");
      expect(level).toBe("INFO");
    });
  });
});
