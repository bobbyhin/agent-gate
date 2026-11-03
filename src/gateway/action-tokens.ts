// Action tokens: how a human confirms an irreversible call (docs/adr/0013-action-tokens-for-irreversible-calls.md).
//
// A policy rule with "irreversible": true asks like any other rule, and its yes needs more than a
// yes. When the call asks, the gateway picks a random nonce for the request. The token is derived
// from it and from the call, under a key of the gateway's own:
//
//   code    "at-" and 8 characters (40 bits). The CLI shows it to the human, in the read-back of
//           "approvals approve" and in "approvals show", and the human gives it back: typed, or with
//           --token. That is the confirmation. "--yes" alone is not one, and the agent is never shown
//           the code: it is not in any tool result, and not in the audit log.
//   proof   a full HMAC-SHA256 that the CLI writes into the approval once the code checks out. The
//           gateway checks it before the call runs, so an approval written by anything but the CLI (an
//           edited approvals.json) lets nothing through.
//
// Both are HMAC-SHA256 over the request's binding: its id, server, tool, argsHash, agent, expiry and
// nonce. A token for one request is worth nothing for another: other arguments, a later request for
// the same call, a copy of the record with a new expiry. The gateway also remembers the nonces that
// let a call through (in memory, and from the audit log when it starts), so an old approval restored
// into approvals.json is refused as a replay.
//
// The key file is the one thing an agent must not be able to read or change: a key it can read lets it
// make proofs, and a file it can write lets it put in a key it knows. Keep it where the agent's own
// tools do not reach (another OS user, a path its sandbox denies). Then the agent can neither approve
// its own calls with the CLI nor forge an approval, even if it can write approvals.json.

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { StringDecoder } from "node:string_decoder";

/** The key's file name in the state directory, when the config does not name another file. */
export const KEY_FILE_NAME = "action-token.key";
/** Crockford's base32: no I, L, O or U, so a code reads back without doubt. */
const CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CODE_CHARS = 8;

/** What a token is bound to: the request and its call, with the file hashes of a request bound to file content (fileBinding). */
export interface TokenBinding {
  id: string;
  server: string;
  tool: string;
  argsHash: string;
  agent?: string;
  expiresAt: string;
  nonce: string;
  files?: ReadonlyArray<{ argument: string; path: string; sha256: string | null }>;
}

/** The key cannot be read, cannot be written, or is not a key. */
export class ActionTokenError extends Error {
  override name = "ActionTokenError";
}

const NONCE = /^nc-[0-9a-f]{24}$/;

/** A request's nonce: random, picked by the gateway when the call asks. Not a secret: the key is. */
export function newNonce(): string {
  return `nc-${randomBytes(12).toString("hex")}`;
}

/**
 * True for a nonce as the gateway makes them. Anything else in a record (empty, a number, an object)
 * was written by something else, and is never verified or spent: a value that cannot be remembered as
 * spent would let one approval through again and again.
 */
export function isNonce(value: unknown): value is string {
  return typeof value === "string" && NONCE.test(value);
}

export class ActionTokens {
  private cached: Buffer | undefined;

  constructor(readonly keyFile: string) {}

  /**
   * The key. With `create`, a missing key file is written first (32 random bytes as hex, mode 0600);
   * without, a missing key is undefined. A key that cannot be read, that other users can read, or that
   * is not 64 hex digits is an ActionTokenError.
   */
  key(create = false): Buffer | undefined {
    if (this.cached) return this.cached;
    let text: string;
    try {
      text = fs.readFileSync(this.keyFile, "utf8");
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code !== "ENOENT") throw new ActionTokenError(`cannot read the action-token key ${this.keyFile}: ${(err as Error).message}`);
      if (!create) return undefined;
      try {
        fs.mkdirSync(path.dirname(this.keyFile), { recursive: true, mode: 0o700 });
        // "wx": two processes creating it at once both end up reading the one that was written first.
        fs.writeFileSync(this.keyFile, `${randomBytes(32).toString("hex")}\n`, { flag: "wx", mode: 0o600 });
      } catch (writeErr) {
        if ((writeErr as NodeJS.ErrnoException).code !== "EEXIST") throw new ActionTokenError(`cannot create the action-token key ${this.keyFile}: ${(writeErr as Error).message}`);
      }
      return this.key(false);
    }
    if (process.platform !== "win32" && (fs.statSync(this.keyFile).mode & 0o077) !== 0) {
      throw new ActionTokenError(`the action-token key ${this.keyFile} can be read by other users; make it readable by its owner only (chmod 600)`);
    }
    const hex = text.trim();
    if (!/^[0-9a-f]{64}$/.test(hex)) throw new ActionTokenError(`${this.keyFile} is not an action-token key (64 hex digits)`);
    this.cached = Buffer.from(hex, "hex");
    return this.cached;
  }

  /** The code the human gives back: "at-XXXX-XXXX". Creates the key if there is none. */
  code(binding: TokenBinding): string {
    const chars = base32(this.mac("code", binding), CODE_CHARS);
    return `at-${chars.slice(0, 4)}-${chars.slice(4)}`;
  }

  /** Whether what the human typed is this request's code: case, dashes, spaces and the "at-" are not counted. */
  matches(binding: TokenBinding, presented: string): boolean {
    let typed = presented.toUpperCase().replace(/[^0-9A-Z]/g, "");
    if (typed.length === CODE_CHARS + 2 && typed.startsWith("AT")) typed = typed.slice(2);
    const expected = this.code(binding).toUpperCase().replace(/[^0-9A-Z]/g, "").slice(2);
    return typed.length === expected.length && timingSafeEqual(Buffer.from(typed), Buffer.from(expected));
  }

  /** The proof the CLI writes into an approval whose code checked out. Creates the key if there is none. */
  proof(binding: TokenBinding): string {
    return this.mac("proof", binding).toString("hex");
  }

  /** Whether `proof` was made with this key for exactly this binding. False when there is no key, or the nonce is not one the gateway makes. */
  verify(binding: TokenBinding, proof: string | undefined): boolean {
    if (proof === undefined || !/^[0-9a-f]{64}$/.test(proof) || !isNonce(binding.nonce) || this.key(false) === undefined) return false;
    return timingSafeEqual(Buffer.from(proof, "hex"), this.mac("proof", binding));
  }

  private mac(purpose: "code" | "proof", b: TokenBinding): Buffer {
    const key = this.key(true) as Buffer;
    // Every field in a fixed order; the bound files as [argument, path, sha256], so that a hash written
    // into the record after the human's yes does not match.
    // A record written by something else may hold anything here: it is serialized as it is, and fails to match.
    const files = b.files === undefined ? null : Array.isArray(b.files) ? b.files.map((f) => (typeof f === "object" && f !== null ? [f.argument, f.path, f.sha256] : f)) : b.files;
    const message = `agent-gate action token v1 ${purpose}\n${JSON.stringify([b.id, b.server, b.tool, b.argsHash, b.agent ?? null, b.expiresAt, b.nonce, files])}`;
    return createHmac("sha256", key).update(message).digest();
  }
}

/** The first `chars` characters of base32 (Crockford) of `bytes`. */
function base32(bytes: Buffer, chars: number): string {
  let out = "";
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = ((buffer << 8) | byte) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      out += CODE_ALPHABET[(buffer >> (bits - 5)) & 31];
      bits -= 5;
      if (out.length === chars) return out;
    }
  }
  return out;
}

/**
 * The nonces of the calls an action token let through, from the audit log: a forwarded call line
 * with a nonce. Read once when the gateway starts, so a replayed approval is refused after a restart
 * too. Read in pieces, so a long log is not held in memory. A log that cannot be read is reported with
 * `onError`; the gateway then knows only the tokens spent since it started (and a log it cannot read is
 * usually one it cannot write either, and then no call runs at all).
 */
export function spentNonces(auditFile: string, onError: (message: string) => void = () => undefined): Set<string> {
  const spent = new Set<string>();
  let fd: number;
  try {
    fd = fs.openSync(auditFile, "r");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") onError(`cannot read ${auditFile} for the spent action tokens: ${(err as Error).message}`);
    return spent; // no log yet: nothing was spent
  }
  try {
    const chunk = Buffer.alloc(1 << 20);
    // A character split between two pieces is put back together, not read as two broken ones.
    const decoder = new StringDecoder("utf8");
    let rest = "";
    const take = (line: string): void => {
      if (!line.includes('"nonce"')) return;
      try {
        const value = JSON.parse(line) as { forwarded?: unknown; nonce?: unknown };
        if (value.forwarded === true && typeof value.nonce === "string") spent.add(value.nonce);
      } catch {
        // a damaged line: audit verify reports it
      }
    };
    for (;;) {
      const n = fs.readSync(fd, chunk, 0, chunk.length, null);
      if (n === 0) break;
      const lines = (rest + decoder.write(chunk.subarray(0, n))).split("\n");
      rest = lines.pop() ?? "";
      lines.forEach(take);
    }
    take(rest + decoder.end());
  } catch (err) {
    onError(`cannot read ${auditFile} for the spent action tokens: ${(err as Error).message}`);
  } finally {
    fs.closeSync(fd);
  }
  return spent;
}
