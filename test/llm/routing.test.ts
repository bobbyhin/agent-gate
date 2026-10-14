// Table tests for the pure routing function.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { parseLlmConfig } from "../../src/llm/config.js";
import { route, type RouteRequest } from "../../src/llm/routing.js";

const config = parseLlmConfig(
  {
    stateDir: "state",
    policy: "policy.json",
    upstreams: [
      { name: "cheap", baseUrl: "http://cheap.test/v1", apiKeyEnv: "CHEAP_KEY", models: { small: "small-v1", tiny: "tiny-v1" }, pricePerMTok: { input: 0.1, output: 0.4 } },
      {
        name: "strong",
        baseUrl: "http://strong.test/v1",
        apiKeyEnv: "STRONG_KEY",
        models: { large: "large-v2", medium: "medium-v2", small: "small-v2" },
        pricePerMTok: { input: 3, output: 15 },
      },
      { name: "backup", baseUrl: "http://backup.test/v1", apiKeyEnv: "BACKUP_KEY", models: { large: "large-backup" }, pricePerMTok: { input: 3, output: 15 } },
    ],
    routes: [
      { id: "classify-is-cheap", when: { task: ["classify", "extract-*"] }, use: { upstream: "cheap", model: "small" } },
      { id: "code-is-strong", when: { task: "code" }, use: { upstream: "strong", model: "large" }, fallback: { upstream: "backup" } },
      { id: "pin-legacy-names", when: { model: "gpt-*" }, use: { upstream: "strong", model: "small" } },
      { id: "cheap-models", use: { upstream: "cheap" } },
      { id: "strong-models", use: { upstream: "strong" }, fallback: { upstream: "backup" } },
    ],
    keys: [{ name: "k", sha256: "a".repeat(64), dailyUsd: 1, monthlyUsd: 10 }],
  },
  "/srv",
);

type Expected = [rule: string, upstream: string, model: string, fallback?: [upstream: string, model: string]];

describe("routing", () => {
  const table: Array<[name: string, request: RouteRequest, expected: Expected | undefined]> = [
    ["an alias goes to the first upstream that offers it", { model: "small" }, ["cheap-models", "cheap", "small-v1"]],
    ["another alias on the same upstream", { model: "tiny" }, ["cheap-models", "cheap", "tiny-v1"]],
    ["an alias only a later upstream offers skips the earlier rule", { model: "large" }, ["strong-models", "strong", "large-v2", ["backup", "large-backup"]]],
    ["the fallback is left out when it does not offer the alias", { model: "medium" }, ["strong-models", "strong", "medium-v2"]],
    ["x-agent-task beats the alias: classify is cheap", { model: "large", task: "classify" }, ["classify-is-cheap", "cheap", "small-v1"]],
    ["task globs: extract-invoice", { model: "large", task: "extract-invoice" }, ["classify-is-cheap", "cheap", "small-v1"]],
    ["task globs ignore case", { model: "tiny", task: "CODE" }, ["code-is-strong", "strong", "large-v2", ["backup", "large-backup"]]],
    ["a fixed model ignores the requested alias", { model: "tiny", task: "code" }, ["code-is-strong", "strong", "large-v2", ["backup", "large-backup"]]],
    ["an unknown task falls through to the alias rules", { model: "small", task: "summarize" }, ["cheap-models", "cheap", "small-v1"]],
    ["an empty task matches no task rule", { model: "small", task: "" }, ["cheap-models", "cheap", "small-v1"]],
    ["model globs: legacy names are pinned", { model: "gpt-4o", task: "chat" }, ["pin-legacy-names", "strong", "small-v2"]],
    ["no upstream offers the alias", { model: "huge" }, undefined],
    ["aliases are exact: case matters for the lookup", { model: "SMALL" }, undefined],
  ];
  for (const [name, request, expected] of table) {
    it(name, () => {
      const chosen = route(config, request);
      const got: Expected | undefined = chosen && [
        chosen.rule,
        chosen.primary.upstream.name,
        chosen.primary.model,
        ...(chosen.fallback ? [[chosen.fallback.upstream.name, chosen.fallback.model] as [string, string]] : []),
      ] as Expected;
      assert.deepEqual(got, expected);
    });
  }

  it("returns the alias in use and the upstream's price with each target", () => {
    const chosen = route(config, { model: "large", task: "code" });
    assert.equal(chosen?.primary.alias, "large");
    assert.equal(chosen?.fallback?.alias, "large");
    assert.deepEqual(chosen?.primary.upstream.pricePerMTok, { input: 3, output: 15 });
  });

  it("is a pure function: the same request always gets the same route", () => {
    const first = JSON.stringify(route(config, { model: "large", task: "classify" }));
    for (let i = 0; i < 3; i++) assert.equal(JSON.stringify(route(config, { model: "large", task: "classify" })), first);
  });
});
