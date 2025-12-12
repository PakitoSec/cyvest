/**
 * Level enumeration and scoring logic for Cyvest.
 *
 * This module defines the security level classification system and the algorithm
 * for determining levels from scores.
 */

import type {
  Observable,
  Check,
  ThreatIntel,
  Container,
  Level,
} from "./types.generated";

// Re-export Level type from types.generated for convenience
export type { Level } from "./types.generated";

/**
 * Ordered array of levels from lowest to highest severity.
 */
export const LEVEL_ORDER: readonly Level[] = [
  "NONE",
  "TRUSTED",
  "INFO",
  "SAFE",
  "NOTABLE",
  "SUSPICIOUS",
  "MALICIOUS",
] as const;

/**
 * Numeric values for each level (for comparison purposes).
 */
export const LEVEL_VALUES: Record<Level, number> = {
  NONE: 0,
  TRUSTED: 1,
  INFO: 2,
  SAFE: 3,
  NOTABLE: 4,
  SUSPICIOUS: 5,
  MALICIOUS: 6,
};

/**
 * Color mapping for display purposes.
 */
export const LEVEL_COLORS: Record<Level, string> = {
  NONE: "#808080", // gray
  TRUSTED: "#22c55e", // green
  INFO: "#06b6d4", // cyan
  SAFE: "#4ade80", // bright green
  NOTABLE: "#eab308", // yellow
  SUSPICIOUS: "#f97316", // orange
  MALICIOUS: "#ef4444", // red
};

/**
 * Normalize a level input to the Level type.
 *
 * Accepts a case-insensitive string and returns the normalized Level.
 *
 * @param level - Level string (e.g., "malicious", "MALICIOUS")
 * @returns The normalized Level
 * @throws Error if the string does not match a valid Level
 *
 * @example
 * ```ts
 * normalizeLevel("malicious") // => "MALICIOUS"
 * normalizeLevel("TRUSTED") // => "TRUSTED"
 * ```
 */
export function normalizeLevel(level: string): Level {
  const upper = level.toUpperCase();
  if (LEVEL_ORDER.includes(upper as Level)) {
    return upper as Level;
  }
  throw new Error(`Invalid level name: ${level}`);
}

/**
 * Check if a string is a valid Level.
 *
 * @param level - String to check
 * @returns True if valid Level
 */
export function isValidLevel(level: string): level is Level {
  return LEVEL_ORDER.includes(level.toUpperCase() as Level);
}

/**
 * Calculate the security level from a numeric score.
 *
 * Algorithm:
 * - score < 0.0  -> TRUSTED
 * - score === 0.0 -> INFO
 * - score < 3.0  -> NOTABLE
 * - score < 5.0  -> SUSPICIOUS
 * - score >= 5.0 -> MALICIOUS
 *
 * @param score - The numeric score to evaluate
 * @returns The appropriate Level based on the score
 *
 * @example
 * ```ts
 * getLevelFromScore(-1) // => "TRUSTED"
 * getLevelFromScore(0) // => "INFO"
 * getLevelFromScore(2.5) // => "NOTABLE"
 * getLevelFromScore(4) // => "SUSPICIOUS"
 * getLevelFromScore(5) // => "MALICIOUS"
 * ```
 */
export function getLevelFromScore(score: number): Level {
  if (score < 0) {
    return "TRUSTED";
  }
  if (score === 0) {
    return "INFO";
  }
  if (score < 3) {
    return "NOTABLE";
  }
  if (score < 5) {
    return "SUSPICIOUS";
  }
  return "MALICIOUS";
}

/**
 * Compare two levels.
 *
 * @param a - First level
 * @param b - Second level
 * @returns -1 if a < b, 0 if a === b, 1 if a > b
 *
 * @example
 * ```ts
 * compareLevels("INFO", "MALICIOUS") // => -1
 * compareLevels("MALICIOUS", "INFO") // => 1
 * compareLevels("INFO", "INFO") // => 0
 * ```
 */
export function compareLevels(a: Level, b: Level): -1 | 0 | 1 {
  const valueA = LEVEL_VALUES[a];
  const valueB = LEVEL_VALUES[b];
  if (valueA < valueB) return -1;
  if (valueA > valueB) return 1;
  return 0;
}

/**
 * Check if level a is higher (more severe) than level b.
 *
 * @param a - First level
 * @param b - Second level
 * @returns True if a is higher than b
 *
 * @example
 * ```ts
 * isLevelHigherThan("MALICIOUS", "SUSPICIOUS") // => true
 * isLevelHigherThan("INFO", "MALICIOUS") // => false
 * ```
 */
export function isLevelHigherThan(a: Level, b: Level): boolean {
  return LEVEL_VALUES[a] > LEVEL_VALUES[b];
}

/**
 * Check if level a is lower (less severe) than level b.
 *
 * @param a - First level
 * @param b - Second level
 * @returns True if a is lower than b
 */
export function isLevelLowerThan(a: Level, b: Level): boolean {
  return LEVEL_VALUES[a] < LEVEL_VALUES[b];
}

/**
 * Check if level a is at least as severe as level b.
 *
 * @param a - Level to check
 * @param minLevel - Minimum required level
 * @returns True if a is at least minLevel
 *
 * @example
 * ```ts
 * isLevelAtLeast("MALICIOUS", "SUSPICIOUS") // => true
 * isLevelAtLeast("SUSPICIOUS", "SUSPICIOUS") // => true
 * isLevelAtLeast("INFO", "SUSPICIOUS") // => false
 * ```
 */
export function isLevelAtLeast(a: Level, minLevel: Level): boolean {
  return LEVEL_VALUES[a] >= LEVEL_VALUES[minLevel];
}

/**
 * Get the maximum (most severe) level from an array of levels.
 *
 * @param levels - Array of levels
 * @returns The most severe level, or "NONE" if array is empty
 */
export function maxLevel(levels: Level[]): Level {
  if (levels.length === 0) return "NONE";
  return levels.reduce((max, level) =>
    isLevelHigherThan(level, max) ? level : max
  );
}

/**
 * Get the minimum (least severe) level from an array of levels.
 *
 * @param levels - Array of levels
 * @returns The least severe level, or "MALICIOUS" if array is empty
 */
export function minLevel(levels: Level[]): Level {
  if (levels.length === 0) return "MALICIOUS";
  return levels.reduce((min, level) =>
    isLevelLowerThan(level, min) ? level : min
  );
}

/**
 * Get the color associated with a level for display purposes.
 *
 * @param level - Level to get color for
 * @returns Hex color string
 */
export function getColorForLevel(level: Level): string {
  return LEVEL_COLORS[level];
}

/**
 * Get the color associated with a score for display purposes.
 *
 * @param score - Score to get color for
 * @returns Hex color string
 */
export function getColorForScore(score: number): string {
  return getColorForLevel(getLevelFromScore(score));
}

/**
 * Type guard to check if an object has a level property.
 */
export function hasLevel(obj: unknown): obj is { level: Level } {
  return (
    typeof obj === "object" &&
    obj !== null &&
    "level" in obj &&
    typeof (obj as { level: unknown }).level === "string" &&
    isValidLevel((obj as { level: string }).level)
  );
}

/**
 * Extract level from an entity (Observable, Check, ThreatIntel, Container).
 */
export function getEntityLevel(
  entity: Observable | Check | ThreatIntel | Container
): Level {
  if ("aggregated_level" in entity) {
    const aggregatedLevel = entity.aggregated_level;
    if (typeof aggregatedLevel === "string" && isValidLevel(aggregatedLevel)) {
      return aggregatedLevel;
    }
  }
  if ("level" in entity && isValidLevel(entity.level)) {
    return entity.level;
  }
  throw new Error("Entity does not have a valid level.");
}
