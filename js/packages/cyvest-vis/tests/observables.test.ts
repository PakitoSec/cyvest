import { describe, expect, it } from "vitest";

import { parseCyvest } from "@cyvest/cyvest-js";

import { buildInvestigationElements } from "../src/adapters/investigationElements";
import { buildObservablesElements } from "../src/adapters/observablesElements";
import {
  getInvestigationIconSvg,
  getObservableIconSvg,
} from "../src/icons/svg";
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
  it("creates data URI icons for observables and investigation nodes", () => {
    const observableIcon = getObservableIconSvg("domain");
    const investigationIcon = getInvestigationIconSvg("tag");

    expect(observableIcon.startsWith("data:image/svg+xml;utf8,")).toBe(true);
    expect(investigationIcon.startsWith("data:image/svg+xml;utf8,")).toBe(true);
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

  it("builds investigation hierarchy nodes and edges", () => {
    const elements = buildInvestigationElements(investigation);

    const nodes = elements.filter((item) => item.group === "nodes");
    const edges = elements.filter((item) => item.group === "edges");

    expect(nodes.length).toBeGreaterThan(0);
    expect(edges.length).toBeGreaterThan(0);

    const rootNode = nodes.find(
      (node) => (node.data as Record<string, unknown>).nodeType === "root"
    );

    expect(rootNode).toBeDefined();
  });
});
