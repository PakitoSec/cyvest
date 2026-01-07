import { describe, it, expect } from "vitest";
import {
  // Keys
  generateObservableKey,
  generateCheckKey,
  generateThreatIntelKey,
  generateEnrichmentKey,
  generateTagKey,
  parseKeyType,
  validateKey,
  parseObservableKey,
  parseCheckKey,
  parseThreatIntelKey,
  // Levels
  normalizeLevel,
  isValidLevel,
  getLevelFromScore,
  compareLevels,
  isLevelHigherThan,
  isLevelAtLeast,
  maxLevel,
  minLevel,
  LEVEL_ORDER,
  LEVEL_VALUES,
} from "../src";

describe("Key Generation", () => {
  describe("generateObservableKey", () => {
    it("generates correct observable key", () => {
      expect(generateObservableKey("ipv4-addr", "192.168.1.1")).toBe(
        "obs:ipv4-addr:192.168.1.1"
      );
    });

    it("normalizes to lowercase", () => {
      expect(generateObservableKey("IPV4-ADDR", "192.168.1.1")).toBe(
        "obs:ipv4-addr:192.168.1.1"
      );
    });

    it("trims whitespace", () => {
      expect(generateObservableKey("  ipv4-addr  ", "  192.168.1.1  ")).toBe(
        "obs:ipv4-addr:192.168.1.1"
      );
    });
  });

  describe("generateCheckKey", () => {
    it("generates correct check key", () => {
      expect(generateCheckKey("sender_verification")).toBe(
        "chk:sender_verification"
      );
    });
  });

  describe("generateThreatIntelKey", () => {
    it("generates correct threat intel key", () => {
      expect(
        generateThreatIntelKey("virustotal", "obs:ipv4-addr:192.168.1.1")
      ).toBe("ti:virustotal:obs:ipv4-addr:192.168.1.1");
    });
  });

  describe("generateEnrichmentKey", () => {
    it("generates key without context", () => {
      expect(generateEnrichmentKey("whois_data")).toBe("enr:whois_data");
    });

    it("generates key with context hash", () => {
      const key = generateEnrichmentKey("whois_data", "example.com");
      expect(key).toMatch(/^enr:whois_data:[a-f0-9]+$/);
    });
  });

  describe("generateTagKey", () => {
    it("generates correct tag key", () => {
      expect(generateTagKey("header:auth")).toBe("tag:header:auth");
    });

    it("normalizes to lowercase", () => {
      expect(generateTagKey("HEADER:AUTH")).toBe("tag:header:auth");
    });

    it("trims whitespace", () => {
      expect(generateTagKey("  header:auth  ")).toBe("tag:header:auth");
    });
  });

  describe("parseKeyType", () => {
    it("parses observable key type", () => {
      expect(parseKeyType("obs:ipv4-addr:192.168.1.1")).toBe("obs");
    });

    it("parses check key type", () => {
      expect(parseKeyType("chk:sender:email")).toBe("chk");
    });

    it("parses threat intel key type", () => {
      expect(parseKeyType("ti:vt:obs:ip:1.1.1.1")).toBe("ti");
    });

    it("parses enrichment key type", () => {
      expect(parseKeyType("enr:whois")).toBe("enr");
    });

    it("parses tag key type", () => {
      expect(parseKeyType("tag:header:auth")).toBe("tag");
    });

    it("returns null for invalid key", () => {
      expect(parseKeyType("invalid")).toBeNull();
      expect(parseKeyType("foo:bar")).toBeNull();
    });
  });

  describe("validateKey", () => {
    it("validates correct keys", () => {
      expect(validateKey("obs:ipv4-addr:192.168.1.1")).toBe(true);
      expect(validateKey("chk:sender:email")).toBe(true);
    });

    it("validates key type", () => {
      expect(validateKey("obs:ipv4-addr:192.168.1.1", "obs")).toBe(true);
      expect(validateKey("obs:ipv4-addr:192.168.1.1", "chk")).toBe(false);
    });

    it("rejects invalid keys", () => {
      expect(validateKey("")).toBe(false);
      expect(validateKey("invalid")).toBe(false);
      expect(validateKey("foo:bar")).toBe(false);
    });
  });

  describe("parseObservableKey", () => {
    it("parses observable key components", () => {
      expect(parseObservableKey("obs:ipv4-addr:192.168.1.1")).toEqual({
        type: "ipv4-addr",
        value: "192.168.1.1",
      });
    });

    it("handles values with colons", () => {
      expect(parseObservableKey("obs:url:http://example.com:8080")).toEqual({
        type: "url",
        value: "http://example.com:8080",
      });
    });

    it("returns null for invalid key", () => {
      expect(parseObservableKey("chk:sender:email")).toBeNull();
    });
  });

  describe("parseCheckKey", () => {
    it("parses check key components", () => {
      expect(parseCheckKey("chk:sender_verification")).toEqual({
        checkName: "sender_verification",
      });
    });
  });

  describe("parseThreatIntelKey", () => {
    it("parses threat intel key components", () => {
      expect(
        parseThreatIntelKey("ti:virustotal:obs:ipv4-addr:192.168.1.1")
      ).toEqual({
        source: "virustotal",
        observableKey: "obs:ipv4-addr:192.168.1.1",
      });
    });
  });
});

describe("Levels", () => {
  describe("LEVEL_ORDER", () => {
    it("has correct order", () => {
      expect(LEVEL_ORDER).toEqual([
        "NONE",
        "TRUSTED",
        "INFO",
        "SAFE",
        "NOTABLE",
        "SUSPICIOUS",
        "MALICIOUS",
      ]);
    });
  });

  describe("normalizeLevel", () => {
    it("normalizes lowercase input", () => {
      expect(normalizeLevel("malicious")).toBe("MALICIOUS");
      expect(normalizeLevel("info")).toBe("INFO");
    });

    it("accepts uppercase input", () => {
      expect(normalizeLevel("MALICIOUS")).toBe("MALICIOUS");
    });

    it("throws on invalid input", () => {
      expect(() => normalizeLevel("invalid")).toThrow("Invalid level name");
    });
  });

  describe("isValidLevel", () => {
    it("returns true for valid levels", () => {
      expect(isValidLevel("MALICIOUS")).toBe(true);
      expect(isValidLevel("info")).toBe(true);
    });

    it("returns false for invalid levels", () => {
      expect(isValidLevel("invalid")).toBe(false);
    });
  });

  describe("getLevelFromScore", () => {
    it("returns TRUSTED for negative scores", () => {
      expect(getLevelFromScore(-1)).toBe("TRUSTED");
      expect(getLevelFromScore(-0.5)).toBe("TRUSTED");
    });

    it("returns INFO for zero", () => {
      expect(getLevelFromScore(0)).toBe("INFO");
    });

    it("returns NOTABLE for scores < 3", () => {
      expect(getLevelFromScore(0.1)).toBe("NOTABLE");
      expect(getLevelFromScore(2.9)).toBe("NOTABLE");
    });

    it("returns SUSPICIOUS for scores < 5", () => {
      expect(getLevelFromScore(3)).toBe("SUSPICIOUS");
      expect(getLevelFromScore(4.9)).toBe("SUSPICIOUS");
    });

    it("returns MALICIOUS for scores >= 5", () => {
      expect(getLevelFromScore(5)).toBe("MALICIOUS");
      expect(getLevelFromScore(10)).toBe("MALICIOUS");
    });
  });

  describe("compareLevels", () => {
    it("returns -1 when a < b", () => {
      expect(compareLevels("INFO", "MALICIOUS")).toBe(-1);
    });

    it("returns 1 when a > b", () => {
      expect(compareLevels("MALICIOUS", "INFO")).toBe(1);
    });

    it("returns 0 when a === b", () => {
      expect(compareLevels("INFO", "INFO")).toBe(0);
    });
  });

  describe("isLevelHigherThan", () => {
    it("returns true when a is more severe", () => {
      expect(isLevelHigherThan("MALICIOUS", "SUSPICIOUS")).toBe(true);
      expect(isLevelHigherThan("SUSPICIOUS", "INFO")).toBe(true);
    });

    it("returns false when a is less severe or equal", () => {
      expect(isLevelHigherThan("INFO", "MALICIOUS")).toBe(false);
      expect(isLevelHigherThan("INFO", "INFO")).toBe(false);
    });
  });

  describe("isLevelAtLeast", () => {
    it("returns true when a >= minLevel", () => {
      expect(isLevelAtLeast("MALICIOUS", "SUSPICIOUS")).toBe(true);
      expect(isLevelAtLeast("SUSPICIOUS", "SUSPICIOUS")).toBe(true);
    });

    it("returns false when a < minLevel", () => {
      expect(isLevelAtLeast("INFO", "SUSPICIOUS")).toBe(false);
    });
  });

  describe("maxLevel", () => {
    it("returns most severe level", () => {
      expect(maxLevel(["INFO", "MALICIOUS", "SUSPICIOUS"])).toBe("MALICIOUS");
    });

    it("returns NONE for empty array", () => {
      expect(maxLevel([])).toBe("NONE");
    });
  });

  describe("minLevel", () => {
    it("returns least severe level", () => {
      expect(minLevel(["INFO", "MALICIOUS", "SUSPICIOUS"])).toBe("INFO");
    });

    it("returns MALICIOUS for empty array", () => {
      expect(minLevel([])).toBe("MALICIOUS");
    });
  });
});
