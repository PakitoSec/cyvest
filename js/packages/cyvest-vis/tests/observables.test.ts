import { describe, expect, it } from "vitest";

import {
  getInvestigationNodeEmoji,
  getLevelBackgroundColor,
  getLevelColor,
  getObservableEmoji,
  getObservableShape,
  truncateLabel,
} from "../src/utils/observables";

describe("observables utils", () => {
  it("returns emojis for known and unknown observable types", () => {
    expect(getObservableEmoji("domain-name")).toBe("🏠");
    expect(getObservableEmoji("IPv4-Addr")).toBe("🌐");
    expect(getObservableEmoji("unmapped")).toBe("❓");
  });

  it("returns shapes based on type and root flag", () => {
    expect(getObservableShape("domain-name", false)).toBe("square");
    expect(getObservableShape("ipv6-addr", false)).toBe("triangle");
    expect(getObservableShape("anything-else", false)).toBe("circle");
    expect(getObservableShape("anything-else", true)).toBe("rectangle");
  });

  it("truncates long labels in the middle by default", () => {
    expect(truncateLabel("short", 10)).toBe("short");
    expect(truncateLabel("averyverylongvalue", 10)).toBe("ave…lue");
    expect(truncateLabel("averyverylongvalue", 10, false)).toBe("averyvery…");
  });

  it("maps levels to colors and falls back to NONE", () => {
    expect(getLevelColor("SUSPICIOUS")).toBe("#f97316");
    expect(getLevelColor("UNKNOWN")).toBe("#6b7280");
    expect(getLevelBackgroundColor("SUSPICIOUS")).toBe("#ffedd5");
    expect(getLevelBackgroundColor("UNKNOWN")).toBe("#f3f4f6");
  });

  it("returns investigation node emoji with fallback", () => {
    expect(getInvestigationNodeEmoji("root")).toBe("🎯");
    expect(getInvestigationNodeEmoji("missing")).toBe("❓");
  });
});
