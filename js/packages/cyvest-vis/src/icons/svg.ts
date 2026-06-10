import type { InvestigationCyNodeType } from "../types";

export interface IconRenderOptions {
  color?: string;
}

type IconName =
  | "globe"
  | "domain"
  | "link"
  | "mail"
  | "file"
  | "hash"
  | "flask"
  | "question"
  | "crosshair"
  | "finding"
  | "evidence"
  | "tag";

const ICON_PATHS: Record<IconName, string> = {
  globe:
    '<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15 15 0 0 1 0 20 15 15 0 0 1 0-20z"/>',
  domain:
    '<path d="M3 9 12 3l9 6v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M9 22V12h6v10"/>',
  link:
    '<path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7"/><path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 1 0 7 7l1.7-1.7"/>',
  mail:
    '<rect x="2" y="4" width="20" height="16" rx="2"/><path d="m2 7 9 6a2 2 0 0 0 2 0l9-6"/>',
  file:
    '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>',
  hash:
    '<line x1="4" y1="9" x2="20" y2="9"/><line x1="4" y1="15" x2="20" y2="15"/><line x1="10" y1="3" x2="8" y2="21"/><line x1="16" y1="3" x2="14" y2="21"/>',
  flask:
    '<path d="M10 2v7.5a2 2 0 0 1-.2.9L4.7 20.5a1 1 0 0 0 .9 1.5h12.8a1 1 0 0 0 .9-1.5l-5.1-10.1a2 2 0 0 1-.2-.9V2"/><path d="M8.5 2h7"/><path d="M7 16h10"/>',
  question:
    '<circle cx="12" cy="12" r="10"/><path d="M9.1 9a3 3 0 0 1 5.8 1c0 2-3 3-3 3"/><path d="M12 17h.01"/>',
  crosshair:
    '<circle cx="12" cy="12" r="10"/><line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/>',
  finding:
    '<rect x="7" y="3" width="10" height="4" rx="1.5"/><rect x="5" y="5" width="14" height="16" rx="2"/><path d="m9 14 2.5 2.5L16 12"/>',
  evidence:
    '<path d="M4 4h16v16H4z"/><path d="M8 9h8M8 13h8M8 17h5"/>',
  tag:
    '<path d="M20.6 13.4 13.4 20.6a2 2 0 0 1-2.8 0L3.4 13.4a2 2 0 0 1 0-2.8l7.2-7.2a2 2 0 0 1 2.8 0l7.2 7.2a2 2 0 0 1 0 2.8z"/><circle cx="9" cy="9" r="1.2"/>',
};

export const OBSERVABLE_ICON_NAME_MAP: Record<string, IconName> = {
  ipv4: "globe",
  ipv6: "globe",
  domain: "domain",
  url: "link",
  email: "mail",
  hash: "hash",
  file: "file",
  artifact: "flask",
  host: "domain",
  process: "finding",
  user: "mail",
  command_line: "link",
  cloud_resource: "globe",
};

export const INVESTIGATION_ICON_NAME_MAP: Record<InvestigationCyNodeType, IconName> = {
  root: "crosshair",
  finding: "finding",
  evidence: "evidence",
  tag: "tag",
};

function toSvgDataUri(iconName: IconName, color: string): string {
  const body = ICON_PATHS[iconName] ?? ICON_PATHS.question;
  const svg = [
    '<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48"',
    ' viewBox="0 0 24 24" fill="none"',
    ` stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">`,
    body,
    "</svg>",
  ].join("");

  return `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
}

export function getObservableIconSvg(
  observableType: string,
  options?: IconRenderOptions
): string {
  const normalizedType = observableType.toLowerCase().trim();
  const icon = OBSERVABLE_ICON_NAME_MAP[normalizedType] ?? "question";
  return toSvgDataUri(icon, options?.color ?? "#314264");
}

export function getInvestigationIconSvg(
  nodeType: InvestigationCyNodeType,
  options?: IconRenderOptions
): string {
  const icon = INVESTIGATION_ICON_NAME_MAP[nodeType] ?? "question";
  return toSvgDataUri(icon, options?.color ?? "#314264");
}
