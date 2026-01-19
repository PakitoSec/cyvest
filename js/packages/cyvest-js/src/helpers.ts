import Ajv2020, { type ValidateFunction } from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import schema from "../../../../schema/cyvest.schema.json" assert { type: "json" };
import type { CyvestInvestigation } from "./types.generated";

// Use Ajv2020 for draft 2020-12 schema support
const ajv = new Ajv2020({ allErrors: true });
addFormats(ajv);

let validateFn: ValidateFunction | null = null;

function getValidator(): ValidateFunction {
  if (!validateFn) {
    validateFn = ajv.compile(schema);
  }
  return validateFn;
}

export function parseCyvest(json: unknown): CyvestInvestigation {
  const validate = getValidator();
  if (!validate(json)) {
    const msg = ajv.errorsText(validate.errors || []);
    throw new Error(`Invalid Cyvest payload: ${msg}`);
  }
  return json as CyvestInvestigation;
}

export function isCyvest(json: unknown): json is CyvestInvestigation {
  const validate = getValidator();
  return !!validate(json);
}
