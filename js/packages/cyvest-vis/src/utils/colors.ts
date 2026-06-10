import type { Level } from "@cyvest/cyvest-js";
import {
  DEFAULT_CYVEST_THEME,
  type CyvestThemeTokens,
} from "../types";

export function getLevelColor(level: Level): string {
  const colors: Record<Level, string> = {
    NONE: "#cbd5e1",
    TRUSTED: "#94a3b8",
    INFO: "#94a3b8",
    SAFE: "#648b79",
    NOTABLE: "#aa8958",
    SUSPICIOUS: "#ad704b",
    MALICIOUS: "#ad5555",
  };
  return colors[level] ?? colors.INFO;
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

export function getLevelBackgroundColor(
  level: Level,
  theme?: Partial<CyvestThemeTokens>
): string {
  const resolved = resolveTheme(theme);
  return mixHexColor(
    getLevelColor(level),
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
