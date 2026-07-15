import type {
  CyvestRelationshipFamily,
  CyvestRelationshipProfile,
  CyvestRelationshipProfileOverrides,
  CyvestThemeTokens,
} from "../types";
import { resolveTheme } from "../utils/colors";

const FAMILY_DEFAULTS: Record<
  CyvestRelationshipFamily,
  Omit<CyvestRelationshipProfile, "label" | "color">
> = {
  structural: {
    family: "structural",
    distance: 84,
    strength: 0.9,
    width: 1.7,
    lineStyle: "solid",
    dashPattern: [1, 0],
    opacity: 0.88,
  },
  infrastructure: {
    family: "infrastructure",
    distance: 108,
    strength: 0.72,
    width: 1.4,
    lineStyle: "dashed",
    dashPattern: [9, 3],
    opacity: 0.78,
  },
  behavioral: {
    family: "behavioral",
    distance: 132,
    strength: 0.55,
    width: 1.3,
    lineStyle: "dashed",
    dashPattern: [3, 4],
    opacity: 0.78,
  },
  association: {
    family: "association",
    distance: 176,
    strength: 0.16,
    width: 1.2,
    lineStyle: "dotted",
    dashPattern: [1, 5],
    opacity: 0.78,
  },
};

const RELATIONSHIP_FAMILIES: Record<string, CyvestRelationshipFamily> = {
  contains: "structural",
  "derived-from": "structural",
  "resolves-to": "infrastructure",
  hosts: "infrastructure",
  "communicates-with": "behavioral",
  executes: "behavioral",
  "related-to": "association",
};

function humanizeRelationshipType(type: string): string {
  return type
    .split(/[-_]/g)
    .filter(Boolean)
    .map((word) => word[0]?.toUpperCase() + word.slice(1))
    .join(" ");
}

function getFamilyColor(
  family: CyvestRelationshipFamily,
  theme: CyvestThemeTokens
): string {
  return {
    structural: theme.edgeStructuralColor,
    infrastructure: theme.edgeInfrastructureColor,
    behavioral: theme.edgeBehavioralColor,
    association: theme.edgeAssociationColor,
  }[family];
}

export function getRelationshipFamily(type: string): CyvestRelationshipFamily {
  return RELATIONSHIP_FAMILIES[type.toLowerCase()] ?? "association";
}

export function resolveRelationshipProfile(
  type: string,
  options?: {
    theme?: Partial<CyvestThemeTokens>;
    overrides?: CyvestRelationshipProfileOverrides;
    isRootLink?: boolean;
  }
): CyvestRelationshipProfile {
  const normalizedType = type.toLowerCase();
  const family = getRelationshipFamily(normalizedType);
  const theme = resolveTheme(options?.theme);
  const rootOverrides = options?.isRootLink
    ? { distance: 210, strength: 0.24, width: 1.35, opacity: 0.84 }
    : {};
  const custom = options?.overrides?.[normalizedType] ?? options?.overrides?.[type] ?? {};
  const resolvedFamily = custom.family ?? family;

  return {
    ...FAMILY_DEFAULTS[resolvedFamily],
    label: humanizeRelationshipType(type),
    color: getFamilyColor(resolvedFamily, theme),
    ...rootOverrides,
    ...custom,
    family: resolvedFamily,
  };
}

export const BUILT_IN_RELATIONSHIP_TYPES = Object.freeze(
  Object.keys(RELATIONSHIP_FAMILIES)
);
