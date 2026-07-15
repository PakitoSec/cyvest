import { describe, expect, it, vi } from "vitest";
import type { Core } from "cytoscape";

import { parseCyvest } from "@cyvest/cyvest-js";

import { buildObservablesElements } from "../src/adapters/observablesElements";
import { updateLabelDensity } from "../src/components/CytoscapeCanvas";
import { getObservableIconSvg } from "../src/icons/svg";
import {
  computeForcePositions,
  computeSemanticTargets,
  resolveForceLinkStrength,
} from "../src/layout/force";
import { filterInvestigation, normalizeGraphFilters } from "../src/core/filters";
import { resolveRelationshipProfile } from "../src/core/relationships";
import { createObservablesStylesheet } from "../src/core/styles";
import { getLevelColor } from "../src/utils/colors";
import { truncateLabel } from "../src/utils/labels";

import cyvestEmailData from "../../cyvest-app/src/investigations/cyvest_email.json";
import cyvestVisualData from "../../cyvest-app/src/investigations/cyvest_visual.json";

const investigation = parseCyvest(cyvestVisualData);
const emailInvestigation = parseCyvest(cyvestEmailData);

describe("email investigation semantics", () => {
  it("uses precise relationship types instead of generic associations", () => {
    const relationships = Object.values(emailInvestigation.observables).flatMap(
      (observable) => observable.relationships
    );
    const counts = Object.fromEntries(
      [...new Set(relationships.map((relationship) => relationship.relationship_type))]
        .sort()
        .map((type) => [
          type,
          relationships.filter((relationship) => relationship.relationship_type === type).length,
        ])
    );

    expect(counts).toEqual({
      contains: 9,
      "derived-from": 1,
      hosts: 4,
      "resolves-to": 1,
    });
    expect(relationships).not.toContainEqual(
      expect.objectContaining({ relationship_type: "related-to" })
    );
  });

  it("presents the technical root as the investigation subject", () => {
    const root = buildObservablesElements(emailInvestigation).find(
      (element) => element.group === "nodes" && element.data.isRoot === true
    );

    expect(root?.data.labelShort).toBe("Email Investigation");
    expect(root?.data.labelFull).toBe("Email Investigation");
  });
});

describe("label utilities", () => {
  it("truncates long labels in the middle by default", () => {
    expect(truncateLabel("short", 10)).toBe("short");
    expect(truncateLabel("averyverylongvalue", 10)).toBe("avery…alue");
    expect(truncateLabel("averyverylongvalue", 10, false)).toBe("averyvery…");
  });

  it("shows every label on wide canvases and prioritizes labels in compact mode", () => {
    const stylesheet = createObservablesStylesheet();
    const nodeStyle = stylesheet.find((rule) => rule.selector === "node")?.style;
    const compactStyle = stylesheet.find(
      (rule) => rule.selector === "node.cyvest-compact-label"
    )?.style;
    const compactRootStyle = stylesheet.find(
      (rule) => rule.selector === "node[?isRoot].cyvest-compact-label"
    )?.style;

    expect(nodeStyle).toMatchObject({
      label: "data(labelShort)",
      "min-zoomed-font-size": 0,
    });
    expect(compactStyle).toMatchObject({
      label: "data(displayLabel)",
    });
    expect(compactStyle).not.toHaveProperty("min-zoomed-font-size");
    expect(compactRootStyle).toMatchObject({
      "text-halign": "left",
      "text-valign": "center",
    });
  });

  it.each([
    [639, true],
    [640, false],
  ])("sets compact labels at a canvas width of %i", (width, compact) => {
    const toggleClass = vi.fn();
    const cy = {
      nodes: vi.fn(() => ({ toggleClass })),
    } as unknown as Core;

    const result = updateLabelDensity(cy, width);

    expect(toggleClass).toHaveBeenCalledWith("cyvest-compact-label", compact);
    expect(result).toBe(compact);
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
    expect(
      nodes
        .filter((node) => node.data.observableType === "url")
        .every((node) => String(node.data.labelShort).length <= 22)
    ).toBe(true);
    const permanentLabels = nodes
      .map((node) => String(node.data.displayLabel ?? ""))
      .filter(Boolean);
    expect(permanentLabels).toContain("Phishing Email…nvoice #12345");
    expect(permanentLabels.length).toBeLessThan(nodes.length);
  });

  it("maps semantic relationships to distinct visual and physical profiles", () => {
    const structural = resolveRelationshipProfile("contains");
    const infrastructure = resolveRelationshipProfile("resolves-to");
    const behavioral = resolveRelationshipProfile("communicates-with");
    const association = resolveRelationshipProfile("custom-correlation");

    expect(structural).toMatchObject({
      family: "structural",
      distance: 84,
      strength: 0.9,
      lineStyle: "solid",
      dashPattern: [1, 0],
    });
    expect(infrastructure).toMatchObject({
      family: "infrastructure",
      lineStyle: "dashed",
      dashPattern: [9, 3],
    });
    expect(behavioral).toMatchObject({
      family: "behavioral",
      distance: 132,
      lineStyle: "dashed",
      dashPattern: [3, 4],
    });
    expect(association).toMatchObject({
      family: "association",
      distance: 176,
      lineStyle: "dotted",
      dashPattern: [1, 5],
    });
    expect([
      structural.distance,
      infrastructure.distance,
      behavioral.distance,
      association.distance,
    ]).toEqual([...[
      structural.distance,
      infrastructure.distance,
      behavioral.distance,
      association.distance,
    ]].sort((left, right) => left - right));
  });

  it("preserves an explicit zero-strength relationship override", () => {
    const profile = resolveRelationshipProfile("contains", {
      overrides: { contains: { strength: 0 } },
    });

    expect(profile.strength).toBe(0);
    expect(resolveForceLinkStrength(profile.strength, false, {
      linkStrength: 0.16,
      rootLinkStrength: 0.24,
    })).toBe(0);
  });
});

describe("graph filters", () => {
  it("keeps the root while filtering observable and relationship types", () => {
    const filtered = filterInvestigation(
      investigation,
      normalizeGraphFilters({
        observableTypes: ["domain"],
        relationshipTypes: ["resolves-to"],
      })
    );

    expect(Object.values(filtered.observables).some((item) => item.value === "root")).toBe(true);
    expect(
      Object.values(filtered.observables).every(
        (item) =>
          item.value === "root" ||
          item.value === "Phishing Email - Invoice #12345" ||
          item.type === "domain"
      )
    ).toBe(true);
    expect(
      Object.values(filtered.observables)
        .filter((item) => item.value !== "root")
        .flatMap((item) => item.relationships)
        .every((relationship) => relationship.relationship_type === "resolves-to")
    ).toBe(true);
  });
});

describe("force-directed layout", () => {
  it("distributes dense siblings around the root", () => {
    const node = (id: string, label: string, isRoot = false) => ({
      group: "nodes" as const,
      data: { id, labelShort: label, width: 40, height: 40, isRoot },
    });
    const edge = (target: string) => ({
      group: "edges" as const,
      data: {
        id: `root-${target}`,
        source: "root",
        target,
        relationshipFamily: "structural",
        relationshipType: "contains",
      },
    });
    const elements = [
      node("root", "Root", true),
      node("a", "https://long-example.test/first"),
      node("b", "https://long-example.test/second"),
      node("c", "https://long-example.test/third"),
      node("d", "https://long-example.test/fourth"),
      edge("a"),
      edge("b"),
      edge("c"),
      edge("d"),
    ];

    const targets = computeSemanticTargets(elements);
    const siblings = [targets.a, targets.b, targets.c, targets.d];
    const quadrants = new Set(
      siblings.map((target) => `${Math.sign(target.x)},${Math.sign(target.y)}`)
    );

    expect(quadrants.size).toBe(4);
    expect(siblings.every((target) => Math.hypot(target.x, target.y) >= 148)).toBe(true);
  });

  it("keeps weak continuation nodes in their semantic branch", () => {
    const node = (id: string, isRoot = false) => ({
      group: "nodes" as const,
      data: { id, width: 40, height: 40, isRoot },
    });
    const edge = (
      id: string,
      source: string,
      target: string,
      family: "structural" | "association",
      strength: number,
      isRootLink = false
    ) => ({
      group: "edges" as const,
      data: {
        id,
        source,
        target,
        relationshipFamily: family,
        distance: family === "structural" ? 84 : 176,
        strength,
        isRootLink,
      },
    });
    const elements = [
      node("root", true),
      node("a"),
      node("b"),
      node("c"),
      node("d"),
      edge("root-a", "root", "a", "association", 0.24, true),
      edge("a-b", "a", "b", "structural", 0.9),
      edge("b-c", "b", "c", "association", 0.16),
      edge("c-d", "c", "d", "association", 0.16),
    ];

    const targets = computeSemanticTargets(elements);

    expect(Math.hypot(targets.a.x, targets.a.y)).toBeGreaterThan(0);
    expect(Math.hypot(targets.b.x, targets.b.y)).toBeGreaterThan(Math.hypot(targets.a.x, targets.a.y));
    expect(Math.hypot(targets.c.x, targets.c.y)).toBeGreaterThan(Math.hypot(targets.b.x, targets.b.y));
    expect(Math.hypot(targets.d.x, targets.d.y)).toBeGreaterThan(Math.hypot(targets.c.x, targets.c.y));
  });

  it("turns infrastructure links between siblings into local tree branches", () => {
    const targets = computeSemanticTargets(buildObservablesElements(emailInvestigation));
    const domain = targets["obs:domain:virus.com"];
    const hostedUrl = targets["obs:url:https://virus.com/payload.exe"];
    const domainRadius = Math.hypot(domain.x, domain.y);
    const hostedUrlRadius = Math.hypot(hostedUrl.x, hostedUrl.y);
    const domainAngle = Math.atan2(domain.y, domain.x);
    const hostedUrlAngle = Math.atan2(hostedUrl.y, hostedUrl.x);

    expect(hostedUrlRadius).toBeGreaterThan(domainRadius);
    expect(Math.abs(hostedUrlAngle - domainAngle)).toBeLessThan(Math.PI / 4);
  });

  it("places cross-linked first-ring branches next to each other", () => {
    const node = (id: string, isRoot = false) => ({
      group: "nodes" as const,
      data: { id, labelShort: id, width: 40, height: 40, isRoot },
    });
    const edge = (id: string, source: string, target: string, family: "structural" | "association") => ({
      group: "edges" as const,
      data: {
        id,
        source,
        target,
        relationshipFamily: family,
        relationshipType: family === "structural" ? "contains" : "related-to",
        direction: family === "structural" ? "outbound" : "bidirectional",
        strength: family === "structural" ? 0.9 : 0.16,
      },
    });
    const elements = [
      node("root", true),
      node("a"),
      node("b"),
      node("c"),
      node("d"),
      edge("root-a", "root", "a", "structural"),
      edge("root-b", "root", "b", "structural"),
      edge("root-c", "root", "c", "structural"),
      edge("root-d", "root", "d", "structural"),
      edge("a-c", "a", "c", "association"),
    ];

    const targets = computeSemanticTargets(elements);
    const angleA = Math.atan2(targets.a.y, targets.a.x);
    const angleC = Math.atan2(targets.c.y, targets.c.x);
    const angularDistance = Math.abs(
      Math.atan2(Math.sin(angleA - angleC), Math.cos(angleA - angleC))
    );

    expect(angularDistance).toBeLessThanOrEqual(Math.PI / 2);
  });

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

  it("places the phishing narrative in semantic rings", () => {
    const elements = buildObservablesElements(investigation);
    const targets = computeSemanticTargets(elements);
    const positions = computeForcePositions(elements);
    const rootId = "obs:artifact:phishing email - invoice #12345";
    const loginId = "obs:url:https://evil-phishing.com/login";
    const domainId = "obs:domain:evil-phishing.com";
    const ipId = "obs:ipv4:185.220.101.50";

    expect(elements.some((element) => element.data.id === "obs:file:root")).toBe(false);
    expect(targets[rootId]).toEqual({ x: 0, y: 0 });
    expect(Math.hypot(targets[loginId].x, targets[loginId].y)).toBeGreaterThan(0);
    expect(Math.hypot(targets[domainId].x, targets[domainId].y)).toBeGreaterThan(
      Math.hypot(targets[loginId].x, targets[loginId].y)
    );
    expect(Math.hypot(targets[ipId].x, targets[ipId].y)).toBeGreaterThan(
      Math.hypot(targets[domainId].x, targets[domainId].y)
    );
    expect(Math.hypot(positions[loginId].x, positions[loginId].y)).toBeGreaterThan(40);
    expect(Math.hypot(positions[domainId].x, positions[domainId].y)).toBeGreaterThan(
      Math.hypot(positions[loginId].x, positions[loginId].y) + 40
    );
    expect(Math.hypot(positions[ipId].x, positions[ipId].y)).toBeGreaterThan(
      Math.hypot(positions[domainId].x, positions[domainId].y) + 40
    );
  });
});
