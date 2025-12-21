/**
 * Utility functions for observable visualization.
 */

import { getColorForLevel, type Level } from "@cyvest/cyvest-js";
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
export function getLevelColor(level: Level): string {
  return getColorForLevel(level);
}

function lightenHexColor(hex: string, amount: number): string {
  const normalized = hex.startsWith("#") ? hex.slice(1) : hex;
  if (normalized.length !== 6) {
    return hex;
  }

  const r = parseInt(normalized.slice(0, 2), 16);
  const g = parseInt(normalized.slice(2, 4), 16);
  const b = parseInt(normalized.slice(4, 6), 16);

  const mix = (channel: number) =>
    Math.max(0, Math.min(255, Math.round(channel + (255 - channel) * amount)));

  const toHex = (channel: number) => channel.toString(16).padStart(2, "0");

  return `#${toHex(mix(r))}${toHex(mix(g))}${toHex(mix(b))}`;
}

/**
 * Get background color for security level (lighter version).
 */
export function getLevelBackgroundColor(level: Level): string {
  return lightenHexColor(getLevelColor(level), 0.85);
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
