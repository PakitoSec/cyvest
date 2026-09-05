/**
 * Parsing and validation.
 *
 * ajv checks the shape; the version check enforces the rule ajv cannot see — a 7.0 SDK must
 * refuse a 7.1 document rather than silently ignore fields it does not know about. Python
 * applies exactly the same rule.
 *
 * Order matters. The schema constrains `schema_version` to the current major, so the minor
 * window is the SDK's job alone; reading and judging the version first also keeps the error
 * message explicit instead of an opaque ajv shape error.
 */

import Ajv2020, { type ValidateFunction } from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import schema from "../../../../schema/cyvest.schema.json" with { type: "json" };
import type { Investigation } from "./types";

export const SCHEMA_VERSION = "7.1.0";

const SEMVER = /^\d+\.\d+\.\d+$/;

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

/**
 * Read the declared schema version, falling back to `"5"` for anything unversioned.
 *
 * A document with no `schema_version` is a pre-v7 document, not a current one: `schema_version`
 * is not in the schema's `required` list, so defaulting it to `SCHEMA_VERSION` would wave every
 * legacy payload straight through. Python's `detect_schema_version` makes the same choice.
 */
export function detectSchemaVersion(json: unknown): string {
  const raw = (json as { schema_version?: unknown } | null)?.schema_version;
  const version = typeof raw === "string" ? raw.trim() : "";
  return SEMVER.test(version) ? version : "5";
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Normalize 7.0 free-text taxonomies once at the input boundary, without mutating the caller. */
function normalizeTaxonomies(json: unknown): unknown {
  if (!isRecord(json) || !isRecord(json.facts) || !isRecord(json.facts.signals)) return json;
  const signals = Object.fromEntries(
    Object.entries(json.facts.signals).map(([key, signal]) => [
      key,
      isRecord(signal) && Array.isArray(signal.taxonomies)
        ? {
            ...signal,
            taxonomies: signal.taxonomies.map((entry: unknown) =>
              typeof entry === "string" ? { name: entry, value: "", verdict: "INFO" } : entry,
            ),
          }
        : signal,
    ]),
  );
  return { ...json, facts: { ...json.facts, signals } };
}

export function parseCyvest(json: unknown): Investigation {
  assertReadableVersion(detectSchemaVersion(json));
  const normalized = normalizeTaxonomies(json);
  const validate = getValidator();
  if (!validate(normalized)) {
    throw new Error(`Invalid Cyvest payload: ${ajv.errorsText(validate.errors || [])}`);
  }
  return normalized as Investigation;
}

/** A type guard cannot normalize its argument: legacy strings need parseCyvest first. */
export function isCyvest(json: unknown): json is Investigation {
  try {
    assertReadableVersion(detectSchemaVersion(json));
    return !!getValidator()(json);
  } catch {
    return false;
  }
}
