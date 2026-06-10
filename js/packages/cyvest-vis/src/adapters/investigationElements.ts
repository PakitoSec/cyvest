import {
  getRootObservable,
  getTagAncestors,
  type Finding,
  type CyvestInvestigation,
  type Level,
  type Tag,
} from "@cyvest/cyvest-js";
import type { ElementDefinition } from "cytoscape";

import type {
  InvestigationCyEdgeData,
  InvestigationCyNodeData,
  InvestigationCyNodeType,
} from "../types";
import { getInvestigationIconSvg } from "../icons/svg";
import { getLevelBackgroundColor, getLevelColor } from "../utils/colors";
import { truncateLabel } from "../utils/labels";

export interface InvestigationAdapterOptions {
  maxLabelLength?: number;
  edgeColor?: string;
}

const ROOT_NODE_ID = "inv-root";

function createNodeData(
  nodeId: string,
  nodeType: InvestigationCyNodeType,
  label: string,
  level: Level,
  score: number,
  maxLabelLength: number
): InvestigationCyNodeData {
  const borderColor = getLevelColor(level);

  const sizeByType: Record<InvestigationCyNodeType, { width: number; height: number }> = {
    root: { width: 190, height: 52 },
    tag: { width: 156, height: 46 },
    finding: { width: 174, height: 52 },
    evidence: { width: 174, height: 46 },
  };

  const dimensions = sizeByType[nodeType];

  return {
    id: nodeId,
    nodeType,
    labelShort: truncateLabel(
      label,
      nodeType === "root" ? maxLabelLength + 4 : maxLabelLength,
      true
    ),
    labelFull: label,
    level,
    score,
    borderColor,
    fillColor: getLevelBackgroundColor(level),
    icon: getInvestigationIconSvg(nodeType, { color: borderColor }),
    width: dimensions.width,
    height: dimensions.height,
    shape: "round-rectangle",
    borderWidth: 2,
  };
}

function getRootLabel(investigation: CyvestInvestigation): {
  value: string;
  level: Level;
  score: number;
} {
  const rootObservable = getRootObservable(investigation);
  if (rootObservable) {
    return {
      value: rootObservable.value,
      level: rootObservable.level,
      score: rootObservable.score,
    };
  }

  const firstObservable = Object.values(investigation.observables)[0];
  if (firstObservable) {
    return {
      value: firstObservable.value,
      level: firstObservable.level,
      score: firstObservable.score,
    };
  }

  return {
    value: investigation.investigation_name ?? investigation.investigation_id,
    level: investigation.level,
    score: investigation.score,
  };
}

function getTagMap(tags: Record<string, Tag>): Map<string, Tag> {
  const map = new Map<string, Tag>();
  for (const tag of Object.values(tags)) {
    map.set(tag.name, tag);
  }
  return map;
}

function createEdge(
  id: string,
  source: string,
  target: string,
  relationshipType: string,
  edgeColor: string
): ElementDefinition {
  const data: InvestigationCyEdgeData = {
    id,
    relationshipType,
    color: edgeColor,
    width: 1.5,
    sourceArrowShape: "none",
    targetArrowShape: "triangle",
  };

  return {
    group: "edges",
    data: {
      ...data,
      source,
      target,
    },
  };
}

export function buildInvestigationElements(
  investigation: CyvestInvestigation,
  options?: InvestigationAdapterOptions
): ElementDefinition[] {
  const maxLabelLength = options?.maxLabelLength ?? 26;
  const edgeColor = options?.edgeColor ?? "#8a95aa";

  const nodes: ElementDefinition[] = [];
  const edges: ElementDefinition[] = [];

  const root = getRootLabel(investigation);
  nodes.push({
    group: "nodes",
    data: createNodeData(
      ROOT_NODE_ID,
      "root",
      root.value,
      root.level,
      root.score,
      maxLabelLength
    ),
  });

  const findings = Object.values(investigation.findings);
  const evidences = Object.values(investigation.evidences);
  const allTags = Object.values(investigation.tags);
  const tagByName = getTagMap(investigation.tags);

  const findingsInTags = new Set<string>();
  for (const tag of allTags) {
    for (const findingKey of tag.findings) {
      findingsInTags.add(findingKey);
    }
  }

  for (const finding of findings) {
    const findingNodeId = `inv-finding:${finding.key}`;
    const nodeData = createNodeData(
      findingNodeId,
      "finding",
      finding.finding_name,
      finding.level,
      finding.score,
      maxLabelLength
    );

    nodes.push({ group: "nodes", data: nodeData });

    if (!findingsInTags.has(finding.key)) {
      edges.push(
        createEdge(
          `inv-edge-root-finding:${finding.key}`,
          ROOT_NODE_ID,
          findingNodeId,
          "contains-finding",
          edgeColor
        )
      );
    }
  }

  for (const evidence of evidences) {
    nodes.push({
      group: "nodes",
      data: createNodeData(
        `inv-evidence:${evidence.key}`,
        "evidence",
        evidence.title,
        "INFO",
        0,
        maxLabelLength
      ),
    });
  }

  for (const finding of findings) {
    for (const link of finding.evidence_links) {
      if (!investigation.evidences[link.evidence_key]) continue;
      edges.push(
        createEdge(
          `inv-edge-finding-evidence:${finding.key}->${link.evidence_key}`,
          `inv-finding:${finding.key}`,
          `inv-evidence:${link.evidence_key}`,
          "supported-by",
          edgeColor
        )
      );
    }
  }

  const tagNames = new Set<string>();
  for (const tag of allTags) {
    tagNames.add(tag.name);
    for (const ancestor of getTagAncestors(tag.name)) {
      tagNames.add(ancestor);
    }
  }

  for (const tagName of tagNames) {
    const tag = tagByName.get(tagName);
    const tagLevel = tag?.direct_level ?? "INFO";
    const tagScore = tag?.direct_score ?? 0;
    const shortTagName = tagName.split(":").pop() ?? tagName;

    nodes.push({
      group: "nodes",
      data: createNodeData(
        `inv-tag:${tagName}`,
        "tag",
        shortTagName,
        tagLevel,
        tagScore,
        maxLabelLength
      ),
    });
  }

  for (const tagName of tagNames) {
    const parts = tagName.split(":");

    if (parts.length === 1) {
      edges.push(
        createEdge(
          `inv-edge-root-tag:${tagName}`,
          ROOT_NODE_ID,
          `inv-tag:${tagName}`,
          "contains-tag",
          edgeColor
        )
      );
      continue;
    }

    const parentName = parts.slice(0, -1).join(":");
    edges.push(
      createEdge(
        `inv-edge-tag:${parentName}->${tagName}`,
        `inv-tag:${parentName}`,
        `inv-tag:${tagName}`,
        "tag-hierarchy",
        edgeColor
      )
    );
  }

  const findingsByKey = new Map<string, Finding>(
    findings.map((finding) => [finding.key, finding])
  );

  for (const tag of allTags) {
    for (const findingKey of tag.findings) {
      if (!findingsByKey.has(findingKey)) {
        continue;
      }

      edges.push(
        createEdge(
          `inv-edge-tag-finding:${tag.name}->${findingKey}`,
          `inv-tag:${tag.name}`,
          `inv-finding:${findingKey}`,
          "tag-finding",
          edgeColor
        )
      );
    }
  }

  return [...nodes, ...edges];
}
