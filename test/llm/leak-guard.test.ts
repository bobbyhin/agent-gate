// Table tests for the leak guard and the shipped llm-policy.example.json.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import * as path from "node:path";
import { loadLeakPolicy } from "../../src/llm/config.js";
import { guardMessages, messageTexts, parseLeakPolicy, type GuardResult } from "../../src/llm/leak-guard.js";
import { ConfigError } from "../../src/gateway/validate.js";
import { FAKE } from "./fake-secrets.js";

// This file runs from dist/test/llm/, three levels below the repository root.
const ROOT = path.join(__dirname, "..", "..", "..");
const policy = loadLeakPolicy(path.join(ROOT, "llm-policy.example.json"));
const user = (content: unknown): unknown[] => [{ role: "user", content }];

function passed(result: GuardResult): Extract<GuardResult, { action: "pass" }> {
  assert.equal(result.action, "pass", JSON.stringify(result));
  return result as Extract<GuardResult, { action: "pass" }>;
}

describe("llm-policy.example.json", () => {
  it("has the six shipped rules, in this order", () => {
    assert.deepEqual(
      policy.rules.map((r) => [r.id, r.action]),
      [
        ["private-key", "block"],
        ["aws-access-key-id", "block"],
        ["github-token", "block"],
        ["slack-token", "block"],
        ["sk-style-key", "block"],
        ["api-key-assignment", "redact"],
      ],
    );
  });
});

describe("leak guard: secrets are blocked by rule id", () => {
  const table: Array<[rule: string, text: string]> = [
    ["private-key", `why does ssh reject this?\n${FAKE.privateKey}`],
    ["private-key", FAKE.privateKeyCutShort],
    ["private-key", FAKE.pgpPrivateKeyHeader],
    ["aws-access-key-id", `aws_access_key_id = ${FAKE.awsAccessKeyId}`],
    ["aws-access-key-id", `the key ${FAKE.awsAccessKeyId}, region us-east-1`],
    ["github-token", `git clone https://${FAKE.githubToken}@github.com/acme/app.git`],
    ["github-token", `GITHUB_TOKEN=${FAKE.githubFineGrainedToken}`],
    ["slack-token", `SLACK_BOT_TOKEN=${FAKE.slackToken}`],
    ["sk-style-key", `OPENAI_API_KEY=${FAKE.skKey}`],
    ["sk-style-key", `client = Client(api_key="${FAKE.skKey}")`],
  ];
  for (const [rule, text] of table) {
    it(`${rule}: ${JSON.stringify(text.slice(0, 50))}`, () => {
      assert.deepEqual(guardMessages(policy, user(text)), { action: "block", rule });
    });
  }

  it("names only the rule: the result carries no matched text", () => {
    const result = guardMessages(policy, user(`use ${FAKE.awsAccessKeyId}`));
    assert.equal(JSON.stringify(result).includes(FAKE.awsAccessKeyId), false);
  });

  it("checks block rules first, on the original text, so a redaction cannot hide a blocked secret", () => {
    const text = `api_key = "${FAKE.apiKeyValue}" and aws_access_key_id = ${FAKE.awsAccessKeyId}`;
    assert.deepEqual(guardMessages(policy, user(text)), { action: "block", rule: "aws-access-key-id" });
  });

  it("reports the first block rule in policy order when several match", () => {
    assert.deepEqual(guardMessages(policy, user(`${FAKE.awsAccessKeyId}\n${FAKE.privateKey}`)), { action: "block", rule: "private-key" });
  });
});

describe("leak guard: api-key-assignment redacts the value and lets the request through", () => {
  const table: Array<[text: string, expected: string]> = [
    [`connect with api_key = "${FAKE.apiKeyValue}" please`, 'connect with api_key = "[REDACTED:api-key-assignment]" please'],
    [`MY_SERVICE_API_KEY=${FAKE.apiKeyValue}fake`, "MY_SERVICE_API_KEY=[REDACTED:api-key-assignment]"],
    ["password: hunter2hunter2hunter2", "password: [REDACTED:api-key-assignment]"],
    ['{"client_secret": "FAKE-0000-fake-0000"}', '{"client_secret": "[REDACTED:api-key-assignment]"}'],
    [`GET /items?api_key=${FAKE.apiKeyValue}fake&page=2`, "GET /items?api_key=[REDACTED:api-key-assignment]&page=2"],
    [`secret_key = '${FAKE.apiKeyValue}' # dev only`, "secret_key = '[REDACTED:api-key-assignment]' # dev only"],
  ];
  for (const [text, expected] of table) {
    it(JSON.stringify(text), () => {
      const result = passed(guardMessages(policy, user(text)));
      assert.deepEqual(result.messages, user(expected));
      assert.deepEqual(result.redactions, [{ rule: "api-key-assignment", count: 1 }]);
    });
  }

  it("counts every match", () => {
    const result = passed(guardMessages(policy, user(`api_key=${FAKE.apiKeyValue}fake\npassword=${FAKE.apiKeyValue}fake`)));
    assert.deepEqual(result.redactions, [{ rule: "api-key-assignment", count: 2 }]);
  });
});

describe("leak guard: no false positives on prose and code without secrets", () => {
  const clean = [
    "Please summarize the attached meeting notes in three bullet points.",
    "Our password policy requires 12 characters and at least one digit.",
    "const apiKey = process.env.OPENAI_API_KEY;",
    "headers: { Authorization: `Bearer ${token}` }",
    "def login(user, password):\n    return check(user, password)",
    "password = get_password_from_vault()",
    'api_key = os.environ["API_KEY"]',
    "const password: string = input;",
    'api_key = "${API_KEY}"',
    '"api_key": "<your-api-key-here>"',
    'api_key: "{{ secrets.API_KEY_2 }}"',
    "access_token_ttl: 3600",
    "password_hash = bcrypt.hash(password, 12)",
    "ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519",
    "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----",
    "-----BEGIN CERTIFICATE-----",
    'git commit -m "fix AKIA prefix parsing"',
    "pip install scikit-learn  # imported as sk-learn in the notes",
    "id 123e4567-e89b-12d3-a456-426614174000 sha e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "xoxo, see you tomorrow",
    "The token budget is 4096 and the max_tokens field is optional.",
    "for (const key of Object.keys(config)) console.log(key, config[key]);",
    "export GITHUB_TOKEN=$(gh auth token)",
    "SECRET_KEY = env('DJANGO_SECRET_KEY')",
  ];
  for (const text of clean) {
    it(JSON.stringify(text.slice(0, 60)), () => {
      const result = passed(guardMessages(policy, user(text)));
      assert.deepEqual(result.redactions, []);
      assert.deepEqual(result.messages, user(text));
    });
  }
});

describe("leak guard: what is scanned", () => {
  const messages = [
    { role: "system", content: "You are terse." },
    {
      role: "user",
      content: [
        { type: "text", text: `token me: api_key=${FAKE.apiKeyValue}fake` },
        { type: "image_url", image_url: { url: `https://img.example/cat.png?api_key=${FAKE.apiKeyValue}fake` } },
      ],
    },
    {
      role: "assistant",
      content: null,
      tool_calls: [{ id: "call_1", type: "function", function: { name: "login", arguments: JSON.stringify({ user: "ops", password: "hunter2hunter2hunter2" }) } }],
    },
    { role: "tool", tool_call_id: "call_1", content: "ok" },
  ];

  it("scans text parts and tool-call arguments, keeps JSON arguments valid, and leaves other parts alone", () => {
    const before = JSON.stringify(messages);
    const result = passed(guardMessages(policy, messages));
    assert.equal(JSON.stringify(messages), before, "the input was not changed");
    const [system, userMessage, assistant, tool] = result.messages as Array<Record<string, any>>;
    assert.equal(system, messages[0], "unchanged messages are not copied");
    assert.equal(tool, messages[3]);
    assert.equal(userMessage?.content[0].text, "token me: api_key=[REDACTED:api-key-assignment]");
    assert.equal(userMessage?.content[1], messages[1]!.content![1], "an image part is not scanned");
    assert.deepEqual(JSON.parse(assistant?.tool_calls[0].function.arguments), { user: "ops", password: "[REDACTED:api-key-assignment]" });
    assert.deepEqual(result.redactions, [{ rule: "api-key-assignment", count: 2 }]);
  });

  it("blocks a secret in tool-call arguments too", () => {
    const call = [{ role: "assistant", tool_calls: [{ id: "c", type: "function", function: { name: "f", arguments: JSON.stringify({ key: FAKE.githubToken }) } }] }];
    assert.deepEqual(guardMessages(policy, call), { action: "block", rule: "github-token" });
  });

  it("lists the scanned strings in order (the cost estimate counts these)", () => {
    assert.deepEqual(messageTexts(messages), [
      "You are terse.",
      `token me: api_key=${FAKE.apiKeyValue}fake`,
      JSON.stringify({ user: "ops", password: "hunter2hunter2hunter2" }),
      "ok",
    ]);
  });

  it("ignores messages that are not objects instead of failing", () => {
    assert.deepEqual(passed(guardMessages(policy, ["just a string", null, 7])).messages, ["just a string", null, 7]);
  });
});

describe("leak guard: policy validation", () => {
  const rule = { id: "r", regex: "secret-[0-9]+", action: "block" };
  const table: Array<[name: string, json: unknown, message: RegExp]> = [
    ["not an object", [], /policy must be an object/],
    ["missing list", {}, /policy\.leakGuard must be an array/],
    ["unknown top-level field", { leakGuard: [], rules: [] }, /policy has an unknown field "rules"/],
    ["unknown rule field", { leakGuard: [{ ...rule, pattern: "x" }] }, /policy\.leakGuard\[0\] has an unknown field "pattern"/],
    ["bad action", { leakGuard: [{ ...rule, action: "warn" }] }, /policy\.leakGuard\[0\]\.action must be one of block, redact/],
    ["g flag", { leakGuard: [{ ...rule, flags: "gi" }] }, /flags may only contain i, m, s and u/],
    ["invalid regex", { leakGuard: [{ ...rule, regex: "(" }] }, /policy\.leakGuard\[0\]\.regex is not a valid regular expression/],
    ["matches empty text", { leakGuard: [{ ...rule, regex: "x*" }] }, /matches empty text/],
    ["duplicate id", { leakGuard: [rule, rule] }, /policy\.leakGuard\[1\]\.id "r" is already used/],
    ["id with a space", { leakGuard: [{ ...rule, id: "my rule" }] }, /policy\.leakGuard\[0\]\.id must be/],
  ];
  for (const [name, json, message] of table) {
    it(`rejects: ${name}`, () => assert.throws(() => parseLeakPolicy(json), (err: unknown) => err instanceof ConfigError && message.test(err.message)));
  }

  it("accepts an empty list (the guard is then off)", () => {
    assert.deepEqual(passed(guardMessages(parseLeakPolicy({ leakGuard: [] }), user(FAKE.awsAccessKeyId))).redactions, []);
  });
});
