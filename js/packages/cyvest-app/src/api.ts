import { parseCyvest } from "@cyvest/cyvest-js";
import type { CyvestInvestigation } from "@cyvest/cyvest-js";

// Import all investigation files
import cyvest_visual from "./investigations/cyvest_visual.json";
import cyvest_email from "./investigations/cyvest_email.json";

// Available investigations
export const INVESTIGATIONS = {
  cyvest_visual: { name: "Visual Demo", data: cyvest_visual },
  cyvest_email: { name: "Email Investigation", data: cyvest_email },
} as const;

export type InvestigationKey = keyof typeof INVESTIGATIONS;

export async function loadInvestigation(
  key: InvestigationKey = "cyvest_visual"
): Promise<CyvestInvestigation> {
  await new Promise((resolve) => setTimeout(resolve, 50));
  // Validate and parse using the schema validator
  return parseCyvest(INVESTIGATIONS[key].data);
}
