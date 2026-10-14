// Small helpers for checking hand-written JSON (the gateway config and the policy).
// Every error names the exact field, for example: policy.rules[2].decision must be one of ...

export class ConfigError extends Error {
  override name = "ConfigError";
}

export function fail(message: string): never {
  throw new ConfigError(message);
}

export function object(value: unknown, at: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail(`${at} must be an object`);
  return value as Record<string, unknown>;
}

export function array(value: unknown, at: string): unknown[] {
  if (!Array.isArray(value)) fail(`${at} must be an array`);
  return value;
}

export function text(value: unknown, at: string): string {
  if (typeof value !== "string" || value === "") fail(`${at} must be a non-empty string`);
  return value;
}

/** Rejects unknown fields, so a typo such as "decison" is an error instead of being ignored. */
export function onlyKeys(value: Record<string, unknown>, allowed: readonly string[], at: string): void {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) fail(`${at} has an unknown field "${key}" (allowed: ${allowed.join(", ")})`);
  }
}
