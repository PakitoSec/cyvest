import { getColorForLevel, type Level } from "@cyvest/cyvest-js";
import {
  DEFAULT_CYVEST_THEME,
  type CyvestThemeTokens,
} from "../types";

export function getLevelColor(level: Level): string {
  return getColorForLevel(level);
}

function clampChannel(channel: number): number {
  return Math.max(0, Math.min(255, Math.round(channel)));
}

export function lightenHexColor(hex: string, ratio: number): string {
  const normalized = hex.startsWith("#") ? hex.slice(1) : hex;
  if (!/^[0-9a-fA-F]{6}$/.test(normalized)) {
    return hex;
  }

  const red = Number.parseInt(normalized.slice(0, 2), 16);
  const green = Number.parseInt(normalized.slice(2, 4), 16);
  const blue = Number.parseInt(normalized.slice(4, 6), 16);

  const mix = (channel: number) =>
    clampChannel(channel + (255 - channel) * ratio)
      .toString(16)
      .padStart(2, "0");

  return `#${mix(red)}${mix(green)}${mix(blue)}`;
}

export function getLevelBackgroundColor(level: Level): string {
  return lightenHexColor(getLevelColor(level), 0.9);
}

export function resolveTheme(
  theme?: Partial<CyvestThemeTokens>
): CyvestThemeTokens {
  return {
    ...DEFAULT_CYVEST_THEME,
    ...theme,
  };
}
