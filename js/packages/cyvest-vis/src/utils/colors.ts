import { getColorForVerdict, type Verdict } from "@cyvest/cyvest-js";
import {
  DEFAULT_CYVEST_THEME,
  type CyvestThemeTokens,
} from "../types";

/**
 * The colour of a verdict.
 *
 * Delegated to the SDK so that a graph node, a table row and a CLI badge never disagree about
 * what `SUSPICIOUS` looks like.
 */
export function getVerdictColor(verdict: Verdict): string {
  return getColorForVerdict(verdict);
}

function clampChannel(channel: number): number {
  return Math.max(0, Math.min(255, Math.round(channel)));
}

function parseHex(hex: string): [number, number, number] | null {
  const normalized = hex.startsWith("#") ? hex.slice(1) : hex;
  if (!/^[0-9a-fA-F]{6}$/.test(normalized)) {
    return null;
  }
  return [
    Number.parseInt(normalized.slice(0, 2), 16),
    Number.parseInt(normalized.slice(2, 4), 16),
    Number.parseInt(normalized.slice(4, 6), 16),
  ];
}

/** Mix `hex` toward `target` by `ratio` (0 = hex, 1 = target). */
export function mixHexColor(hex: string, target: string, ratio: number): string {
  const from = parseHex(hex);
  const to = parseHex(target);
  if (!from || !to) {
    return hex;
  }

  const mix = (a: number, b: number) =>
    clampChannel(a + (b - a) * ratio)
      .toString(16)
      .padStart(2, "0");

  return `#${mix(from[0], to[0])}${mix(from[1], to[1])}${mix(from[2], to[2])}`;
}

export function lightenHexColor(hex: string, ratio: number): string {
  return mixHexColor(hex, "#ffffff", ratio);
}

export function getVerdictBackgroundColor(
  verdict: Verdict,
  theme?: Partial<CyvestThemeTokens>
): string {
  const resolved = resolveTheme(theme);
  return mixHexColor(
    getVerdictColor(verdict),
    resolved.levelSurfaceMix,
    resolved.levelSurfaceMixRatio
  );
}

export function resolveTheme(
  theme?: Partial<CyvestThemeTokens>
): CyvestThemeTokens {
  return {
    ...DEFAULT_CYVEST_THEME,
    ...theme,
  };
}
