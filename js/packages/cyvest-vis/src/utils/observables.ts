/**
 * Utility functions for observable visualization.
 */

import { getColorForLevel, type Level } from "@cyvest/cyvest-js";
import type { ObservableShape } from "../types";

/**
 * Get the shape for an observable type.
 * All non-root nodes are circles for a cleaner look.
 */
export function getObservableShape(
  _observableType: string,
  isRoot: boolean
): ObservableShape {
  // Root nodes get a rounded rectangle (pill shape)
  if (isRoot) {
    return "rectangle";
  }
  // All other nodes are circles
  return "circle";
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

/**
 * Lighten a hex color by a percentage.
 */
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
  return lightenHexColor(getLevelColor(level), 0.88);
}
