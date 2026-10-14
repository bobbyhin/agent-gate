// Fake secrets for the LLM gateway tests. Every value here is made up, and visibly so (FAKE, fake,
// e2e, 0000): none of them is or was a working credential. They only have the shape of real ones,
// so that the leak guard's rules and the key handling can be tested against that shape.
//
// The secret-shaped values are assembled from pieces at run time, so no complete key, token or
// private key header appears anywhere in the source. Secret scanners (gitleaks here, push
// protection on a code host) therefore have nothing to match, and the repository needs no
// allowlist.
const join = (...parts: string[]): string => parts.join("");

/** Text the leak guard must catch. */
export const FAKE = {
  privateKey: [
    join("-----BEGIN OPENSSH ", "PRIVATE KEY-----"),
    "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE",
    join("-----END OPENSSH ", "PRIVATE KEY-----"),
  ].join("\n"),
  /** Pasted and cut off: a block rule must not need the END line. */
  privateKeyCutShort: join("-----BEGIN RSA ", "PRIVATE KEY-----", "\nFAKEFAKEFAKE (pasted, cut short)"),
  pgpPrivateKeyHeader: join("-----BEGIN PGP ", "PRIVATE KEY BLOCK-----"),
  awsAccessKeyId: join("AKIA", "FAKEFAKEFAKEFAKE"),
  githubToken: join("ghp", "_", "FAKEfakeFAKEfake00000000000000000000"),
  githubFineGrainedToken: join("github", "_pat_", "FAKEfakeFAKEfake0000_000000000000000000000000000000000000"),
  slackToken: join("xo", "xb-", "0000000000-0000000000-FAKEfakeFAKEfake"),
  skKey: join("sk-", "proj-", "FAKEfake0000FAKEfake0000"),
  /** A value for api_key = "...": long enough and with a digit, so the redact rule takes it. */
  apiKeyValue: "fake0000fake0000",
} as const;

/** Upstream provider keys for the end-to-end test, by the environment variable that holds each. */
export const FAKE_PROVIDER_KEYS = {
  E2E_CHEAP_KEY: "fake-provider-key-cheap-e2e-0001",
  E2E_STRONG_KEY: "fake-provider-key-strong-e2e-0002",
  E2E_FLAKY_KEY: "fake-provider-key-flaky-e2e-0003",
  E2E_WRONG_KEY: "fake-provider-key-wrong-e2e-0004",
} as const;

/** Gateway keys for the end-to-end test; the config holds only their SHA-256. */
export const FAKE_GATEWAY_KEYS = {
  teamA: "fake-gateway-key-team-a-e2e",
  teamB: "fake-gateway-key-team-b-e2e",
} as const;
