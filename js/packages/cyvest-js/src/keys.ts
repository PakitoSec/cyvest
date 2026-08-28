/**
 * Key generation utilities for Cyvest objects.
 *
 * Provides deterministic, unique key generation for all object types.
 * Keys are used for object identification, retrieval, and merging.
 */

/**
 * Key type prefixes used in Cyvest.
 */
export type KeyType = "obs" | "fnd" | "evd" | "sig" | "rel" | "dec" | "tag";

/** Every prefix a v7 document can carry. `enr:` is gone — enrichments are evidence now. */
export const KEY_PREFIXES: readonly KeyType[] = ["obs", "fnd", "evd", "sig", "rel", "dec", "tag"] as const;

/**
 * Normalize a string value for consistent key generation.
 */
function normalizeValue(value: string): string {
  return value.trim().toLowerCase();
}

function normalizeObservableValue(
  obsType: string,
  value: string,
  subtype?: string
): string {
  const normalizedType = normalizeValue(obsType);
  const normalizedSubtype = subtype ? normalizeValue(subtype) : undefined;
  const stripped = value.trim();

  if (normalizedType === "command_line") return stripped;
  if (normalizedType === "email" || normalizedType === "host") {
    return stripped.toLowerCase();
  }
  if (
    normalizedType === "user" &&
    (normalizedSubtype === "email" || normalizedSubtype === "upn")
  ) {
    return stripped.toLowerCase();
  }
  if (normalizedSubtype === "uid" || normalizedSubtype === "pid") {
    if (!/^[+-]?\d+$/.test(stripped)) {
      throw new Error(`${normalizedSubtype} observable values must be base-10 integers`);
    }
    return BigInt(stripped).toString(10);
  }
  return stripped;
}

function sha256(content: string): string {
  const bytes = new TextEncoder().encode(content);
  const words: number[] = [];
  const bitLength = bytes.length * 8;
  for (const byte of bytes) {
    words.push(byte);
  }
  words.push(0x80);
  while ((words.length % 64) !== 56) words.push(0);
  for (let i = 7; i >= 0; i--) {
    words.push(Math.floor(bitLength / 2 ** (i * 8)) & 0xff);
  }

  const h = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ];
  const k = Array.from({ length: 64 }, (_, index) => {
    let primeCount = 0;
    let candidate = 2;
    while (true) {
      let prime = true;
      for (let divisor = 2; divisor * divisor <= candidate; divisor++) {
        if (candidate % divisor === 0) {
          prime = false;
          break;
        }
      }
      if (prime && primeCount++ === index) {
        return Math.floor((Math.cbrt(candidate) % 1) * 2 ** 32) >>> 0;
      }
      candidate++;
    }
  });
  const rotateRight = (value: number, amount: number) =>
    (value >>> amount) | (value << (32 - amount));

  for (let offset = 0; offset < words.length; offset += 64) {
    const schedule = new Array<number>(64);
    for (let i = 0; i < 16; i++) {
      const base = offset + i * 4;
      schedule[i] =
        ((words[base] << 24) |
          (words[base + 1] << 16) |
          (words[base + 2] << 8) |
          words[base + 3]) >>>
        0;
    }
    for (let i = 16; i < 64; i++) {
      const s0 =
        rotateRight(schedule[i - 15], 7) ^
        rotateRight(schedule[i - 15], 18) ^
        (schedule[i - 15] >>> 3);
      const s1 =
        rotateRight(schedule[i - 2], 17) ^
        rotateRight(schedule[i - 2], 19) ^
        (schedule[i - 2] >>> 10);
      schedule[i] = (schedule[i - 16] + s0 + schedule[i - 7] + s1) >>> 0;
    }

    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const s1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
      const choice = (e & f) ^ (~e & g);
      const temp1 = (hh + s1 + choice + k[i] + schedule[i]) >>> 0;
      const s0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
      const majority = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (s0 + majority) >>> 0;
      hh = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }
    [a, b, c, d, e, f, g, hh].forEach((value, index) => {
      h[index] = (h[index] + value) >>> 0;
    });
  }
  return h.map((value) => value.toString(16).padStart(8, "0")).join("");
}

function encodeKeyPart(value: string, keepSlash = false): string {
  let encoded = encodeURIComponent(value).replace(/[!'()*]/g, (char) =>
    `%${char.charCodeAt(0).toString(16).toUpperCase()}`
  );
  encoded = encoded.replace(/%40/gi, "@");
  if (keepSlash) encoded = encoded.replace(/%2F/gi, "/").replace(/%5C/gi, "\\");
  return encoded;
}

/**
 * Generate a unique key for an observable.
 *
 * Format: obs:{type}:{normalized_value}
 *
 * @param obsType - Type of observable (ip, url, domain, hash, etc.)
 * @param value - Value of the observable
 * @returns Unique observable key
 *
 * @example
 * ```ts
 * generateObservableKey("ipv4", "192.168.1.1")
 * // => "obs:ipv4:192.168.1.1"
 * ```
 */
export function generateObservableKey(
  obsType: string,
  value: string,
  subtype?: string,
  namespace?: string
): string {
  const normalizedType = normalizeValue(obsType);
  const normalizedSubtype = subtype ? normalizeValue(subtype) : undefined;
  const normalizedNamespace = namespace?.trim().toLowerCase() || undefined;
  const normalizedValue = normalizeObservableValue(
    normalizedType,
    value,
    normalizedSubtype
  );
  const identity = JSON.stringify({
    namespace: normalizedNamespace ?? null,
    subtype: normalizedSubtype ?? null,
    type: normalizedType,
    value: normalizedValue,
  });

  if (
    normalizedType === "command_line" ||
    new TextEncoder().encode(identity).length > 128
  ) {
    return `obs:${normalizedType}:sha256:${sha256(identity)}`;
  }
  if (!normalizedSubtype && !normalizedNamespace) {
    return `obs:${normalizedType}:${normalizedValue.toLowerCase()}`;
  }

  const parts = ["obs", encodeKeyPart(normalizedType), normalizedSubtype ? encodeKeyPart(normalizedSubtype) : "_"];
  if (normalizedNamespace) parts.push(encodeKeyPart(normalizedNamespace));
  parts.push(encodeKeyPart(normalizedValue, true));
  return parts.join(":");
}

/**
 * Generate a finding key.
 *
 * Format: `fnd:{rule_id}`, or `fnd:{rule_id}:{external_id}`.
 *
 * A finding is identified by the rule that produced it. Running the same rule on several
 * observables means several findings, so pass an `externalId` to keep them apart — usually the
 * observable key.
 *
 * @example
 * ```ts
 * generateFindingKey("url_in_body")
 * // => "fnd:url_in_body"
 * ```
 */
export function generateFindingKey(ruleId: string, externalId?: string): string {
  const normalizedRule = normalizeValue(ruleId);
  if (externalId) {
    return `fnd:${normalizedRule}:${externalId.trim()}`;
  }
  return `fnd:${normalizedRule}`;
}

/**
 * Generate an observable-signal key.
 *
 * Format: `sig:{source}:{subject_key}`. The prefix names the *family*, not its first member:
 * v6's `ti:` would have locked every future signal kind behind a threat-intel name.
 *
 * @example
 * ```ts
 * generateSignalKey("virustotal", "obs:ipv4:192.168.1.1")
 * // => "sig:virustotal:obs:ipv4:192.168.1.1"
 * ```
 */
export function generateSignalKey(source: string, subjectKey: string, externalId?: string): string {
  const normalizedSource = normalizeValue(source);
  if (externalId) {
    return `sig:${normalizedSource}:${externalId.trim()}:${subjectKey}`;
  }
  return `sig:${normalizedSource}:${subjectKey}`;
}

/** Kept under its v6 name; new code calls {@link generateSignalKey}. */
export const generateThreatIntelKey = generateSignalKey;

/**
 * Generate a relation key.
 *
 * Format: `rel:{kind}:{source_key}>{target_key}` — direction lives in the key itself, so no
 * `direction` field is needed to disambiguate.
 */
export function generateRelationKey(
  sourceKey: string,
  targetKey: string,
  kind: string,
  externalId?: string,
): string {
  const normalizedKind = normalizeValue(kind);
  if (externalId) {
    return `rel:${normalizedKind}:${externalId.trim()}:${sourceKey}>${targetKey}`;
  }
  return `rel:${normalizedKind}:${sourceKey}>${targetKey}`;
}

/**
 * Generate a decision key.
 *
 * Format: `dec:{target_key}` — one decision per target, whatever it says. The kind is content,
 * not identity: a target holds a single current stance, and changing one's mind is a
 * re-assertion the merge law settles by freshness.
 */
export function generateDecisionKey(targetKey: string): string {
  return `dec:${targetKey}`;
}

/**
 * Generate a unique key for a tag.
 *
 * Format: tag:{normalized_name}
 *
 * @param name - Name of the tag (can use : as hierarchy delimiter)
 * @returns Unique tag key
 *
 * @example
 * ```ts
 * generateTagKey("header:auth:dkim")
 * // => "tag:header:auth:dkim"
 * ```
 */
export function generateTagKey(name: string): string {
  const normalizedName = normalizeValue(name);
  return `tag:${normalizedName}`;
}

/**
 * Get all ancestor tag names from a hierarchical tag name.
 *
 * @param name - Tag name with : delimiter
 * @returns Array of ancestor tag names
 *
 * @example
 * ```ts
 * getTagAncestors("header:auth:dkim")
 * // => ["header", "header:auth"]
 * ```
 */
export function getTagAncestors(name: string): string[] {
  const parts = name.split(":");
  const ancestors: string[] = [];
  for (let i = 0; i < parts.length - 1; i++) {
    ancestors.push(parts.slice(0, i + 1).join(":"));
  }
  return ancestors;
}

/**
 * Check if a tag is a direct child of another tag.
 *
 * @param childName - Potential child tag name
 * @param parentName - Potential parent tag name
 * @returns True if childName is a direct child of parentName
 *
 * @example
 * ```ts
 * isTagChildOf("header:auth", "header") // => true
 * isTagChildOf("header:auth:dkim", "header") // => false (grandchild)
 * ```
 */
export function isTagChildOf(childName: string, parentName: string): boolean {
  if (!childName.startsWith(parentName + ":")) {
    return false;
  }
  const remaining = childName.slice(parentName.length + 1);
  return !remaining.includes(":");
}

/**
 * Check if a tag is a descendant of another tag (any depth).
 *
 * @param descendantName - Potential descendant tag name
 * @param ancestorName - Potential ancestor tag name
 * @returns True if descendantName is a descendant of ancestorName
 *
 * @example
 * ```ts
 * isTagDescendantOf("header:auth:dkim", "header") // => true
 * isTagDescendantOf("header", "header") // => false (same)
 * ```
 */
export function isTagDescendantOf(descendantName: string, ancestorName: string): boolean {
  return descendantName.startsWith(ancestorName + ":");
}

/**
 * Extract the type prefix from a key.
 *
 * @param key - The key to parse
 * @returns Type prefix (see {@link KEY_PREFIXES}) or null if invalid
 *
 * @example
 * ```ts
 * parseKeyType("obs:ipv4:192.168.1.1") // => "obs"
 * parseKeyType("invalid") // => null
 * ```
 */
export function parseKeyType(key: string): KeyType | null {
  if (key.includes(":")) {
    const prefix = key.split(":", 1)[0] as KeyType;
    if ((KEY_PREFIXES as readonly string[]).includes(prefix)) {
      return prefix;
    }
  }
  return null;
}

/**
 * Validate a key format and optionally finding its type.
 *
 * @param key - The key to validate
 * @param expectedType - Optional expected type prefix
 * @returns True if valid, false otherwise
 *
 * @example
 * ```ts
 * validateKey("obs:ipv4:192.168.1.1") // => true
 * validateKey("obs:ipv4:192.168.1.1", "obs") // => true
 * validateKey("obs:ipv4:192.168.1.1", "chk") // => false
 * validateKey("invalid") // => false
 * ```
 */
export function validateKey(key: string, expectedType?: KeyType): boolean {
  if (!key || !key.includes(":")) {
    return false;
  }

  const keyType = parseKeyType(key);
  if (!keyType) {
    return false;
  }

  if (expectedType && keyType !== expectedType) {
    return false;
  }

  return true;
}

/**
 * Extract components from an observable key.
 *
 * Only reliable for the simple form `obs:{type}:{value}`. A key carrying a subtype or a
 * namespace, and a `command_line` or oversized key folded into `obs:{type}:sha256:{digest}`,
 * both return the remaining segments verbatim as `value` — a key is an identity token, not a
 * record. Read the observable from the document instead of parsing its key.
 *
 * @param key - Observable key to parse
 * @returns Object with type and value, or null if invalid
 *
 * @example
 * ```ts
 * parseObservableKey("obs:ipv4:192.168.1.1")
 * // => { type: "ipv4", value: "192.168.1.1" }
 * ```
 */
export function parseObservableKey(
  key: string
): { type: string; value: string } | null {
  if (!validateKey(key, "obs")) {
    return null;
  }
  const parts = key.split(":");
  if (parts.length >= 3) {
    return {
      type: parts[1],
      value: parts.slice(2).join(":"), // Handle values with colons
    };
  }
  return null;
}
