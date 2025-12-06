/**
 * Utility functions for observable visualization.
 */

import type { ObservableShape } from "../types";

/**
 * Map observable types to emojis.
 */
const OBSERVABLE_EMOJI_MAP: Record<string, string> = {
  // Network
  "ipv4-addr": "🌐",
  "ipv6-addr": "🌐",
  "domain-name": "🏠",
  url: "🔗",
  "autonomous-system": "🌍",
  "mac-addr": "📶",

  // Email
  "email-addr": "📧",
  "email-message": "✉️",

  // File
  file: "📄",
  "file-hash": "🔐",
  "file:hash:md5": "🔐",
  "file:hash:sha1": "🔐",
  "file:hash:sha256": "🔐",

  // User/Identity
  user: "👤",
  "user-account": "👤",
  identity: "🪪",

  // Process/System
  process: "⚙️",
  software: "💿",
  "windows-registry-key": "📝",

  // Threat Intelligence
  "threat-actor": "👹",
  malware: "🦠",
  "attack-pattern": "⚔️",
  campaign: "🎯",
  indicator: "🚨",

  // Artifacts
  artifact: "🧪",
  certificate: "📜",
  "x509-certificate": "📜",

  // Default
  unknown: "❓",
};

/**
 * Get the emoji for an observable type.
 * Falls back to a generic icon if type is unknown.
 */
export function getObservableEmoji(observableType: string): string {
  const normalized = observableType.toLowerCase().trim();
  return OBSERVABLE_EMOJI_MAP[normalized] ?? OBSERVABLE_EMOJI_MAP.unknown;
}

/**
 * Map observable types to shapes.
 */
const OBSERVABLE_SHAPE_MAP: Record<string, ObservableShape> = {
  // Domains get squares
  "domain-name": "square",

  // URLs get circles
  url: "circle",

  // IPs get triangles
  "ipv4-addr": "triangle",
  "ipv6-addr": "triangle",

  // Root/files get rectangles (default for root)
  file: "rectangle",
  "email-message": "rectangle",
};

/**
 * Get the shape for an observable type.
 */
export function getObservableShape(
  observableType: string,
  isRoot: boolean
): ObservableShape {
  if (isRoot) {
    return "rectangle";
  }
  const normalized = observableType.toLowerCase().trim();
  return OBSERVABLE_SHAPE_MAP[normalized] ?? "circle";
}

/**
 * Truncate a label, optionally in the middle for long strings.
 */
export function truncateLabel(
  value: string,
  maxLength: number = 20,
  truncateMiddle: boolean = true
): string {
  if (value.length <= maxLength) {
    return value;
  }

  if (truncateMiddle) {
    const halfLen = Math.floor((maxLength - 3) / 2);
    return `${value.slice(0, halfLen)}…${value.slice(-halfLen)}`;
  }

  return `${value.slice(0, maxLength - 1)}…`;
}

/**
 * Get color for security level.
 */
export function getLevelColor(level: string): string {
  const colors: Record<string, string> = {
    NONE: "#6b7280", // gray-500
    TRUSTED: "#22c55e", // green-500
    INFO: "#3b82f6", // blue-500
    SAFE: "#22c55e", // green-500
    NOTABLE: "#eab308", // yellow-500
    SUSPICIOUS: "#f97316", // orange-500
    MALICIOUS: "#ef4444", // red-500
  };
  return colors[level] ?? colors.NONE;
}

/**
 * Get background color for security level (lighter version).
 */
export function getLevelBackgroundColor(level: string): string {
  const colors: Record<string, string> = {
    NONE: "#f3f4f6", // gray-100
    TRUSTED: "#dcfce7", // green-100
    INFO: "#dbeafe", // blue-100
    SAFE: "#dcfce7", // green-100
    NOTABLE: "#fef9c3", // yellow-100
    SUSPICIOUS: "#ffedd5", // orange-100
    MALICIOUS: "#fee2e2", // red-100
  };
  return colors[level] ?? colors.NONE;
}

/**
 * Emoji map for investigation node types.
 */
const INVESTIGATION_NODE_EMOJI: Record<string, string> = {
  root: "🎯",
  check: "✅",
  container: "📦",
};

/**
 * Get emoji for investigation node type.
 */
export function getInvestigationNodeEmoji(nodeType: string): string {
  return INVESTIGATION_NODE_EMOJI[nodeType] ?? "❓";
}
