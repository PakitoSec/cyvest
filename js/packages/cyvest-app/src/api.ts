import { parseCyvest } from "@cyvest/cyvest-js";
import type { CyvestInvestigation } from "@cyvest/cyvest-js";
import example from "./investigations/cyvest_investigation.json";

export async function loadInvestigation(): Promise<CyvestInvestigation> {
  await new Promise((resolve) => setTimeout(resolve, 50));
  return parseCyvest(example);
}
