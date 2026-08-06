import type React from "react";

import type { CyvestThemeTokens } from "../types";
import { resolveTheme } from "../utils/colors";

export function createThemeStyle(
  theme: Partial<CyvestThemeTokens> | undefined,
  width: number | string,
  height: number | string
): React.CSSProperties {
  const resolved = resolveTheme(theme);

  return {
    width,
    height,
    "--cyvest-background": resolved.background,
    "--cyvest-grid-color": resolved.gridColor,
    "--cyvest-panel-bg": resolved.panelBackground,
    "--cyvest-panel-border": resolved.panelBorder,
    "--cyvest-panel-text": resolved.panelText,
    "--cyvest-panel-muted": resolved.panelTextMuted,
    "--cyvest-accent": resolved.accent,
    "--cyvest-selection-surface": resolved.selectionSurface,
    "--cyvest-edge-extraction": resolved.edgeExtractionColor,
    "--cyvest-edge-pivot": resolved.edgePivotColor,
    "--cyvest-edge-association": resolved.edgeAssociationColor,
    "--cyvest-font-family": resolved.fontFamily,
  } as React.CSSProperties;
}
