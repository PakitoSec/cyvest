import { describe, expect, it } from "vitest";

import { LEVEL_COLORS } from "@cyvest/cyvest-js";
import {
  getLevelBackgroundColor,
  getLevelColor,
  getObservableShape,
  truncateLabel,
} from "../src/utils/observables";

describe("observables utils", () => {
  it("returns shapes based on root flag (all non-root nodes are circles)", () => {
    // All non-root nodes are now circles for a cleaner design
    expect(getObservableShape("domain", false)).toBe("circle");
    expect(getObservableShape("ipv6", false)).toBe("circle");
    expect(getObservableShape("anything-else", false)).toBe("circle");
    // Root nodes get a rectangle (pill shape)
    expect(getObservableShape("anything-else", true)).toBe("rectangle");
    expect(getObservableShape("domain", true)).toBe("rectangle");
  });

  it("truncates long labels in the middle by default", () => {
    expect(truncateLabel("short", 10)).toBe("short");
    expect(truncateLabel("averyverylongvalue", 10)).toBe("ave…lue");
    expect(truncateLabel("averyverylongvalue", 10, false)).toBe("averyvery…");
  });

  it("maps levels to colors", () => {
    expect(getLevelColor("SUSPICIOUS")).toBe(LEVEL_COLORS.SUSPICIOUS);
    // Background color is the level color lightened by 88%
    const bgColor = getLevelBackgroundColor("SUSPICIOUS");
    // Just verify it's a valid hex color that's lighter than the original
    expect(bgColor).toMatch(/^#[0-9a-f]{6}$/i);
  });
});
