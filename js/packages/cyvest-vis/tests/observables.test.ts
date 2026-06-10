import { describe, expect, it } from "vitest";

import { parseCyvest, type CyvestInvestigation } from "@cyvest/cyvest-js";

import { buildInvestigationElements } from "../src/adapters/investigationElements";
import { buildObservablesElements } from "../src/adapters/observablesElements";
import {
  getInvestigationIconSvg,
  getObservableIconSvg,
} from "../src/icons/svg";
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

  it("uses compact neutral shapes for investigation entities", () => {
    const withEvidence = structuredClone(investigation) as CyvestInvestigation;
    const finding = Object.values(withEvidence.findings)[0];
    const evidenceKey = "evd:test:event-1";
    withEvidence.evidences[evidenceKey] = {
      type: "event",
      title: "Process event",
      description: "",
      source: "test",
      external_id: "event-1",
      content: { pid: 42 },
      uri: null,
      captured_at: "2026-06-10T20:00:00Z",
      extra: {},
      key: evidenceKey,
      finding_links: finding ? [finding.key] : [],
    };
    if (finding) {
      finding.evidence_links.push({ evidence_key: evidenceKey });
    }

    const elements = buildInvestigationElements(withEvidence);
    const nodes = elements.filter((item) => item.group === "nodes");
    const root = nodes.find(
      (node) => (node.data as Record<string, unknown>).nodeType === "root"
    );
    const findingNode = nodes.find(
      (node) => (node.data as Record<string, unknown>).nodeType === "finding"
    );
    const evidence = nodes.find(
      (node) => (node.data as Record<string, unknown>).nodeType === "evidence"
    );

    expect(root?.data.shape).toBe("ellipse");
    expect(root?.data.fillColor).toBe("#1e293b");
    expect(findingNode?.data.width).toBeLessThanOrEqual(42);
    expect(evidence?.data.shape).toBe("round-rectangle");
  });
});

describe("force-directed layout", () => {
  it("computes deterministic finite positions around the root", () => {
    const elements = buildObservablesElements(investigation);
    const first = computeForcePositions(elements, "observables");
    const second = computeForcePositions(elements, "observables");
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
