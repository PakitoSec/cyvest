/**
 * Verdicts: the single scale, both asserted and computed.
 *
 * v7 merged `Level` into `Verdict`, so there is no `getLevelFromScore` here and no threshold
 * table to keep in sync with Python. A score already carries its verdict in the report — this
 * module only labels and orders what the report says.
 */

import type { Verdict } from "./types.generated";

export type { Verdict } from "./types.generated";

/** Ordered from most exculpatory to most inculpatory. */
export const VERDICT_ORDER: readonly Verdict[] = ["SAFE", "INFO", "NOTABLE", "SUSPICIOUS", "MALICIOUS"] as const;

const VERDICT_RANK: Record<Verdict, number> = {
  SAFE: 0,
  INFO: 1,
  NOTABLE: 2,
  SUSPICIOUS: 3,
  MALICIOUS: 4,
};

/**
 * Rich style names, mirroring the Python terminal renderer.
 *
 * These are *not* CSS colours: a browser cannot draw `orange3`. Use {@link VERDICT_HEX_COLORS}
 * for anything rendered on screen.
 */
export const VERDICT_TERMINAL_STYLES: Record<Verdict, string> = {
  SAFE: "bright_green",
  INFO: "cyan",
  NOTABLE: "yellow",
  SUSPICIOUS: "orange3",
  MALICIOUS: "red",
};

/** The web palette: muted enough that a wall of NOTABLE nodes stays readable. */
export const VERDICT_HEX_COLORS: Record<Verdict, string> = {
  SAFE: "#648b79",
  INFO: "#94a3b8",
  NOTABLE: "#aa8958",
  SUSPICIOUS: "#ad704b",
  MALICIOUS: "#ad5555",
};

/** Direction the judgment pushes: -1 exculpatory, 0 neutral, +1 inculpatory. */
export function verdictPolarity(verdict: Verdict): -1 | 0 | 1 {
  if (verdict === "SAFE") return -1;
  if (verdict === "INFO") return 0;
  return 1;
}

export function isValidVerdict(value: unknown): value is Verdict {
  return typeof value === "string" && value in VERDICT_RANK;
}

export function normalizeVerdict(value: unknown): Verdict {
  const upper = typeof value === "string" ? value.toUpperCase() : "";
  return isValidVerdict(upper) ? upper : "INFO";
}

export function compareVerdicts(a: Verdict, b: Verdict): number {
  return VERDICT_RANK[a] - VERDICT_RANK[b];
}

export function isVerdictAtLeast(verdict: Verdict, floor: Verdict): boolean {
  return VERDICT_RANK[verdict] >= VERDICT_RANK[floor];
}

export function maxVerdict(verdicts: readonly Verdict[]): Verdict {
  return verdicts.reduce<Verdict>((best, current) => (compareVerdicts(current, best) > 0 ? current : best), "SAFE");
}

export function minVerdict(verdicts: readonly Verdict[]): Verdict {
  return verdicts.reduce<Verdict>(
    (best, current) => (compareVerdicts(current, best) < 0 ? current : best),
    "MALICIOUS",
  );
}

export function getColorForVerdict(verdict: Verdict): string {
  return VERDICT_HEX_COLORS[verdict] ?? VERDICT_HEX_COLORS.INFO;
}

/** Coarse bands for display; the engine works in floats. */
export function confidenceBand(confidence: number): "low" | "medium" | "high" {
  if (confidence < 0.5) return "low";
  if (confidence < 0.85) return "medium";
  return "high";
}
