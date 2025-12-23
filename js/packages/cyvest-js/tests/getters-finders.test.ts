import { describe, it, expect, beforeEach } from "vitest";
import type { CyvestInvestigation } from "../src";
import {
  // Getters
  getObservable,
  getObservableByTypeValue,
  getCheck,
  getCheckByIdScope,
  getAllChecks,
  getThreatIntel,
  getThreatIntelBySourceObservable,
  getAllThreatIntels,
  getEnrichment,
  getEnrichmentByName,
  getAllEnrichments,
  getContainer,
  getContainerByPath,
  getAllContainers,
  getAllObservables,
  getCounts,
  // Finders
  findObservablesByType,
  findObservablesByLevel,
  findObservablesAtLeast,
  findObservablesByValue,
  findInternalObservables,
  findWhitelistedObservables,
  findChecksByScope,
  findChecksByLevel,
  findChecksAtLeast,
  findThreatIntelBySource,
  getChecksForObservable,
  getThreatIntelsForObservable,
  getObservablesForCheck,
  getHighestScoringObservables,
  getMaliciousObservables,
  getAllScopes,
  getAllObservableTypes,
} from "../src";

// Test fixture
function createTestInvestigation(): CyvestInvestigation {
  return {
    investigation_id: "01HXYZTESTINVESTIGATION",
    investigation_name: "Test Investigation",
    started_at: "2024-01-01T00:00:00Z",
    score: 7.5,
    score_display: "7.50",
    level: "MALICIOUS",
    whitelisted: false,
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
      network: [
        {
          key: "chk:ip_check:network",
          check_id: "ip_check",
          scope: "network",
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
      ],
      dns: [
        {
          key: "chk:domain_check:dns",
          check_id: "domain_check",
          scope: "dns",
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
        {
          key: "chk:dns_lookup:dns",
          check_id: "dns_lookup",
          scope: "dns",
          description: "DNS lookup",
          comment: "",
          extra: {},
          score: 0,
          score_display: "0.00",
          level: "INFO",
          origin_investigation_id: "01HXYZTESTINVESTIGATION",
          observable_links: [],
        },
      ],
    },
    checks_by_level: {
      INFO: ["chk:ip_check:network", "chk:dns_lookup:dns"],
      MALICIOUS: ["chk:domain_check:dns"],
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
        taxonomies: [{ verdict: "malicious" }],
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
    containers: {
      "ctr:email": {
        key: "ctr:email",
        path: "email",
        description: "Email container",
        checks: [],
        sub_containers: {
          "ctr:email/headers": {
            key: "ctr:email/headers",
            path: "email/headers",
            description: "Email headers",
            checks: ["chk:ip_check:network"],
            sub_containers: {},
            aggregated_score: 0,
            aggregated_level: "INFO",
          },
        },
        aggregated_score: 0,
        aggregated_level: "INFO",
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
      checks_by_scope: { network: 1, dns: 2 },
      checks_by_level: { INFO: 2, MALICIOUS: 1 },
      total_threat_intel: 1,
      threat_intel_by_source: { virustotal: 1 },
      threat_intel_by_level: { MALICIOUS: 1 },
      total_containers: 2,
    },
    data_extraction: {
      root_type: "email-message",
      score_mode: "max",
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
      const check = getCheck(inv, "chk:domain_check:dns");
      expect(check).toBeDefined();
      expect(check?.check_id).toBe("domain_check");
    });
  });

  describe("getCheckByIdScope", () => {
    it("finds check by id and scope", () => {
      const check = getCheckByIdScope(inv, "domain_check", "dns");
      expect(check).toBeDefined();
      expect(check?.key).toBe("chk:domain_check:dns");
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

  describe("getContainer", () => {
    it("returns top-level container", () => {
      const container = getContainer(inv, "ctr:email");
      expect(container).toBeDefined();
      expect(container?.path).toBe("email");
    });

    it("returns nested container", () => {
      const container = getContainer(inv, "ctr:email/headers");
      expect(container).toBeDefined();
      expect(container?.path).toBe("email/headers");
    });
  });

  describe("getAllContainers", () => {
    it("returns all containers including nested", () => {
      const containers = getAllContainers(inv);
      expect(containers).toHaveLength(2);
    });
  });

  describe("getCounts", () => {
    it("returns correct counts", () => {
      const counts = getCounts(inv);
      expect(counts.observables).toBe(4);
      expect(counts.checks).toBe(3);
      expect(counts.threatIntels).toBe(1);
      expect(counts.enrichments).toBe(1);
      expect(counts.containers).toBe(2);
      expect(counts.whitelists).toBe(1);
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

  describe("findChecksByScope", () => {
    it("finds checks in scope", () => {
      const dnsChecks = findChecksByScope(inv, "dns");
      expect(dnsChecks).toHaveLength(2);
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

  describe("getChecksForObservable", () => {
    it("finds checks that reference observable", () => {
      const checks = getChecksForObservable(inv, "obs:ipv4-addr:192.168.1.1");
      expect(checks).toHaveLength(1);
      expect(checks[0].check_id).toBe("ip_check");
    });
  });

  describe("getThreatIntelsForObservable", () => {
    it("finds threat intel for observable", () => {
      const tis = getThreatIntelsForObservable(
        inv,
        "obs:domain-name:example.com"
      );
      expect(tis).toHaveLength(1);
      expect(tis[0].source).toBe("virustotal");
    });
  });

  describe("getObservablesForCheck", () => {
    it("finds observables referenced by check", () => {
      const obs = getObservablesForCheck(inv, "chk:ip_check:network");
      expect(obs).toHaveLength(1);
      expect(obs[0].value).toBe("192.168.1.1");
    });
  });

  describe("getHighestScoringObservables", () => {
    it("returns top scoring observables", () => {
      const top = getHighestScoringObservables(inv, 2);
      expect(top).toHaveLength(2);
      expect(top[0].score).toBeGreaterThanOrEqual(top[1].score);
    });
  });

  describe("getMaliciousObservables", () => {
    it("returns malicious observables", () => {
      const mal = getMaliciousObservables(inv);
      expect(mal).toHaveLength(2);
    });
  });

  describe("getAllScopes", () => {
    it("returns all scopes", () => {
      const scopes = getAllScopes(inv);
      expect(scopes).toContain("network");
      expect(scopes).toContain("dns");
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
});
