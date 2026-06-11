import { describe, expect, it } from "vitest";

import { parseCyvest } from "@cyvest/cyvest-js";

import { buildObservablesElements } from "../src/adapters/observablesElements";
import { getObservableIconSvg } from "../src/icons/svg";
import { computeForcePositions } from "../src/layout/force";
import { getLevelColor } from "../src/utils/colors";
import { truncateLabel } from "../src/utils/labels";

import cyvestVisualData from "../../cyvest-app/src/investigations/cyvest_visual.json";

const investigation = parseCyvest(cyvestVisualData);

describe("label utilities", () => {
  it("truncates long labels in the middle by default", () => {
    expect(truncateLabel("short", 10)).toBe("short");
    expect(truncateLabel("averyverylongvalue", 10)).toBe("avery…alue");
    expect(truncateLabel("averyverylongvalue", 10, false)).toBe("averyvery…");
  });
});

describe("icon helpers", () => {
  it("creates data URI icons for observables", () => {
    const observableIcon = getObservableIconSvg("domain");

    expect(observableIcon.startsWith("data:image/svg+xml;utf8,")).toBe(true);
  });
});

describe("cytoscape adapters", () => {
  it("builds observable nodes and edges", () => {
    const elements = buildObservablesElements(investigation);

    const nodes = elements.filter((item) => item.group === "nodes");
    const edges = elements.filter((item) => item.group === "edges");

    expect(nodes.length).toBeGreaterThan(0);
    expect(edges.length).toBeGreaterThan(0);

    const firstNodeData = nodes[0]?.data as Record<string, unknown>;
    expect(typeof firstNodeData.labelShort).toBe("string");
    expect(typeof firstNodeData.icon).toBe("string");
  });
});

describe("force-directed layout", () => {
  it("computes deterministic finite positions around the root", () => {
    const elements = buildObservablesElements(investigation);
    const first = computeForcePositions(elements);
    const second = computeForcePositions(elements);
    const root = elements.find(
      (element) =>
        element.group === "nodes" &&
        (element.data as Record<string, unknown>).isRoot === true
    );

    expect(first).toEqual(second);
    expect(Object.keys(first)).toHaveLength(
      elements.filter((element) => element.group === "nodes").length
    );
    expect(first[String(root?.data.id)]).toEqual({ x: 0, y: 0 });
    expect(
      Object.values(first).every(
        (position) =>
          Number.isFinite(position.x) && Number.isFinite(position.y)
      )
    ).toBe(true);
    expect(
      Object.values(first).some(
        (position) => Math.abs(position.x) > 20 || Math.abs(position.y) > 20
      )
    ).toBe(true);
  });

  it("uses a restrained level palette", () => {
    expect(getLevelColor("INFO")).toBe("#94a3b8");
    expect(getLevelColor("MALICIOUS")).toBe("#ad5555");
  });
});
