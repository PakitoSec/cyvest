/**
 * Parsing and validation.
 *
 * ajv checks the shape; the version check enforces the rule ajv cannot see — a 7.0 SDK must
 * refuse a 7.1 document rather than silently ignore fields it does not know about. Python
 * applies exactly the same rule.
 */

import Ajv2020, { type ValidateFunction } from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import schema from "../../../../schema/cyvest.schema.json" assert { type: "json" };
import type { Investigation } from "./types";

export const SCHEMA_VERSION = "7.0.0";

const ajv = new Ajv2020({ allErrors: true });
addFormats(ajv);

let validateFn: ValidateFunction | null = null;

function getValidator(): ValidateFunction {
  if (!validateFn) {
    validateFn = ajv.compile(schema);
  }
  return validateFn;
}

function versionTuple(version: string): [number, number] {
  const [major, minor] = version.split(".");
  return [Number(major), Number(minor)];
}

/** Upward compatibility only: read older documents, never newer ones. */
export function assertReadableVersion(version: string): void {
  const [docMajor, docMinor] = versionTuple(version);
  const [libMajor, libMinor] = versionTuple(SCHEMA_VERSION);

  if (docMajor > libMajor || (docMajor === libMajor && docMinor > libMinor)) {
    throw new Error(
      `Document schema ${version} is newer than this SDK (${SCHEMA_VERSION}); upgrade @cyvest/cyvest-js.`,
    );
  }
  if (docMajor < libMajor) {
    throw new Error(`Document schema ${version} predates this SDK (${SCHEMA_VERSION}); run 'cyvest migrate'.`);
  }
}

export function parseCyvest(json: unknown): Investigation {
  const validate = getValidator();
  if (!validate(json)) {
    throw new Error(`Invalid Cyvest payload: ${ajv.errorsText(validate.errors || [])}`);
  }
  const document = json as Investigation;
  assertReadableVersion(document.schema_version ?? SCHEMA_VERSION);
  return document;
}

export function isCyvest(json: unknown): json is Investigation {
  try {
    parseCyvest(json);
    return true;
  } catch {
    return false;
  }
}
