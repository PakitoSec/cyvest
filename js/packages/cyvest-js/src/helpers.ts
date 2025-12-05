import Ajv, { type ValidateFunction } from "ajv";
import schema from "../../../../schema/cyvest.schema.json" assert { type: "json" };
import type { CyvestInvestigation } from "./types.generated";

const ajv = new Ajv({ allErrors: true, strict: true });

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
