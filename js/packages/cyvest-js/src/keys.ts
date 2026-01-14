/**
 * Key generation utilities for Cyvest objects.
 *
 * Provides deterministic, unique key generation for all object types.
 * Keys are used for object identification, retrieval, and merging.
 */

/**
 * Key type prefixes used in Cyvest.
 */
export type KeyType = "obs" | "chk" | "ti" | "enr" | "tag";

/**
 * Normalize a string value for consistent key generation.
 */
function normalizeValue(value: string): string {
  return value.trim().toLowerCase();
}

/**
 * Create a deterministic hash from a string using a simple hash algorithm.
 * Uses a subset of characters for shorter keys.
 */
function hashString(content: string, length: number = 16): string {
  // Simple hash implementation (similar to Java's hashCode)
  // For production, consider using crypto.subtle or a library
  let hash = 0;
  for (let i = 0; i < content.length; i++) {
    const char = content.charCodeAt(i);
    hash = ((hash << 5) - hash + char) | 0;
  }
  // Convert to hex and pad/truncate
  const hex = Math.abs(hash).toString(16).padStart(8, "0");
  return hex.slice(0, length);
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
export function generateObservableKey(obsType: string, value: string): string {
  const normalizedType = normalizeValue(obsType);
  const normalizedValue = normalizeValue(value);
  return `obs:${normalizedType}:${normalizedValue}`;
}

/**
 * Generate a unique key for a check.
 *
 * Format: chk:{check_name}
 *
 * @param checkName - Name of the check
 * @returns Unique check key
 *
 * @example
 * ```ts
 * generateCheckKey("sender_verification")
 * // => "chk:sender_verification"
 * ```
 */
export function generateCheckKey(checkName: string): string {
  const normalizedName = normalizeValue(checkName);
  return `chk:${normalizedName}`;
}

/**
 * Generate a unique key for threat intelligence.
 *
 * Format: ti:{normalized_source}:{observable_key}
 *
 * @param source - Name of the threat intel source
 * @param observableKey - Key of the related observable
 * @returns Unique threat intel key
 *
 * @example
 * ```ts
 * generateThreatIntelKey("virustotal", "obs:ipv4:192.168.1.1")
 * // => "ti:virustotal:obs:ipv4:192.168.1.1"
 * ```
 */
export function generateThreatIntelKey(
  source: string,
  observableKey: string
): string {
  const normalizedSource = normalizeValue(source);
  return `ti:${normalizedSource}:${observableKey}`;
}

/**
 * Generate a unique key for an enrichment.
 *
 * Format: enr:{name} or enr:{name}:{context_hash}
 *
 * @param name - Name of the enrichment
 * @param context - Optional context string for disambiguation
 * @returns Unique enrichment key
 *
 * @example
 * ```ts
 * generateEnrichmentKey("whois_data")
 * // => "enr:whois_data"
 *
 * generateEnrichmentKey("whois_data", "domain:example.com")
 * // => "enr:whois_data:a1b2c3d4"
 * ```
 */
export function generateEnrichmentKey(name: string, context?: string): string {
  const normalizedName = normalizeValue(name);
  if (context) {
    const contextHash = hashString(context, 8);
    return `enr:${normalizedName}:${contextHash}`;
  }
  return `enr:${normalizedName}`;
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
 * @returns Type prefix (obs, chk, ti, enr, tag) or null if invalid
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
    if (["obs", "chk", "ti", "enr", "tag"].includes(prefix)) {
      return prefix;
    }
  }
  return null;
}

/**
 * Validate a key format and optionally check its type.
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

/**
 * Extract components from a check key.
 *
 * @param key - Check key to parse
 * @returns Object with checkName, or null if invalid
 *
 * @example
 * ```ts
 * parseCheckKey("chk:sender_verification")
 * // => { checkName: "sender_verification" }
 * ```
 */
export function parseCheckKey(
  key: string
): { checkName: string } | null {
  if (!validateKey(key, "chk")) {
    return null;
  }
  const parts = key.split(":");
  if (parts.length >= 2) {
    return {
      checkName: parts.slice(1).join(":"),
    };
  }
  return null;
}

/**
 * Extract components from a threat intel key.
 *
 * @param key - Threat intel key to parse
 * @returns Object with source and observableKey, or null if invalid
 *
 * @example
 * ```ts
 * parseThreatIntelKey("ti:virustotal:obs:ipv4:192.168.1.1")
 * // => { source: "virustotal", observableKey: "obs:ipv4:192.168.1.1" }
 * ```
 */
export function parseThreatIntelKey(
  key: string
): { source: string; observableKey: string } | null {
  if (!validateKey(key, "ti")) {
    return null;
  }
  const parts = key.split(":");
  if (parts.length >= 3) {
    return {
      source: parts[1],
      observableKey: parts.slice(2).join(":"),
    };
  }
  return null;
}
