import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { secretFindings } from "./secret-policy.mjs";

const TOP_LEVEL_KEYS = [
  "agentRunId",
  "ticket",
  "repository",
  "verificationStepCodes",
  "limits",
  "riskCodes",
];
const TICKET_KEYS = [
  "key",
  "title",
  "description",
  "type",
  "status",
  "priority",
  "labels",
  "acceptanceCriteria",
  "parentKey",
  "childKeys",
  "blockerKeys",
];
const REPOSITORY_KEYS = [
  "fullName",
  "id",
  "baseBranch",
  "baseSha",
  "allowedPaths",
  "forbiddenPaths",
];
const LIMIT_KEYS = [
  "maxRuntimeSeconds",
  "maxChangedFiles",
  "maxDiffBytes",
  "costCeilingMinor",
  "costCurrency",
];

function assertExactKeys(value, keys, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const extras = Object.keys(value).filter((key) => !keys.includes(key));
  const missing = keys.filter((key) => !(key in value));
  if (extras.length > 0 || missing.length > 0) {
    throw new Error(`${label} has unexpected or missing fields`);
  }
}

function assertString(value, label, maxLength, nullable = false) {
  if (nullable && value === null) return;
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maxLength ||
    /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value)
  ) {
    throw new Error(`${label} is invalid`);
  }
}

function assertStringArray(value, label, maxItems, maxLength) {
  if (
    !Array.isArray(value) ||
    value.length > maxItems ||
    value.some((item) => {
      try {
        assertString(item, label, maxLength);
        return false;
      } catch {
        return true;
      }
    })
  ) {
    throw new Error(`${label} is invalid`);
  }
}

function assertExactStringSet(value, expected, label) {
  assertStringArray(value, label, 64, 200);
  assertStringArray(expected, `trusted ${label}`, 64, 200);
  if (
    new Set(value).size !== value.length ||
    new Set(expected).size !== expected.length ||
    JSON.stringify([...value].sort()) !== JSON.stringify([...expected].sort())
  ) {
    throw new Error(`${label} does not match trusted policy`);
  }
}

export function validateContext(context, policy) {
  assertExactKeys(context, TOP_LEVEL_KEYS, "context");
  assertExactKeys(context.ticket, TICKET_KEYS, "context.ticket");
  assertExactKeys(context.repository, REPOSITORY_KEYS, "context.repository");
  assertExactKeys(context.limits, LIMIT_KEYS, "context.limits");
  if (secretFindings(context.ticket).length > 0) {
    throw new Error("RUNNER_CONTEXT_SECRET_DENIED");
  }

  assertString(context.agentRunId, "agentRunId", 36);
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      context.agentRunId,
    )
  ) {
    throw new Error("agentRunId is not a UUID");
  }

  for (const [field, maxLength, nullable] of [
    ["key", 32, false],
    ["title", 200, false],
    ["description", 8000, false],
    ["type", 40, false],
    ["status", 40, false],
    ["priority", 40, false],
    ["parentKey", 32, true],
  ]) {
    assertString(context.ticket[field], `ticket.${field}`, maxLength, nullable);
  }
  assertStringArray(context.ticket.labels, "ticket.labels", 32, 80);
  assertStringArray(
    context.ticket.acceptanceCriteria,
    "ticket.acceptanceCriteria",
    24,
    500,
  );
  assertStringArray(context.ticket.childKeys, "ticket.childKeys", 32, 32);
  assertStringArray(context.ticket.blockerKeys, "ticket.blockerKeys", 32, 32);

  const repository = context.repository;
  const exactRepositoryChecks = [
    ["fullName", repository.fullName, policy.repository.fullName],
    ["id", repository.id, policy.repository.id],
    ["baseBranch", repository.baseBranch, policy.repository.defaultBranch],
  ];
  for (const [name, actual, expected] of exactRepositoryChecks) {
    if (actual !== expected) {
      throw new Error(`repository.${name} does not match trusted policy`);
    }
  }
  if (!/^[0-9a-f]{40}$/.test(repository.baseSha)) {
    throw new Error("repository.baseSha is not a full commit SHA");
  }
  assertExactStringSet(
    repository.allowedPaths,
    policy.patch.allowedPaths,
    "repository.allowedPaths",
  );
  assertExactStringSet(
    repository.forbiddenPaths,
    policy.patch.forbiddenPaths,
    "repository.forbiddenPaths",
  );

  if (
    JSON.stringify(context.verificationStepCodes) !==
    JSON.stringify(policy.verification.stepCodes)
  ) {
    throw new Error("verification step codes do not match trusted policy");
  }
  if (
    context.limits.maxChangedFiles !== policy.patch.maxChangedFiles ||
    context.limits.maxDiffBytes !== policy.patch.maxDiffBytes ||
    context.limits.maxRuntimeSeconds !== policy.codex.maxRuntimeSeconds ||
    context.limits.costCeilingMinor !== policy.limits.costCeilingMinor ||
    context.limits.costCurrency !== policy.limits.costCurrency
  ) {
    throw new Error("context limits do not match trusted policy");
  }
  assertStringArray(context.riskCodes, "riskCodes", 16, 64);
  return context;
}

export function renderPrompt(template, context, policy) {
  validateContext(context, policy);
  const serialized = JSON.stringify(context, null, 2)
    .replaceAll("<", "\\u003c")
    .replaceAll(">", "\\u003e");
  const hash = createHash("sha256").update(serialized).digest("hex");
  return `${template.trim()}\n\nUNTRUSTED_TICKET_DATA_SHA256: ${hash}\n<UNTRUSTED_TICKET_DATA_JSON>\n${serialized}\n</UNTRUSTED_TICKET_DATA_JSON>\n`;
}

async function main() {
  const [contextPath, policyPath, templatePath, outputPath] =
    process.argv.slice(2);
  if (!contextPath || !policyPath || !templatePath || !outputPath) {
    throw new Error(
      "usage: node prepare-context.mjs <context> <policy> <template> <output>",
    );
  }
  const [contextText, policyText, template] = await Promise.all([
    readFile(contextPath, "utf8"),
    readFile(policyPath, "utf8"),
    readFile(templatePath, "utf8"),
  ]);
  const prompt = renderPrompt(
    template,
    JSON.parse(contextText),
    JSON.parse(policyText),
  );
  await writeFile(outputPath, prompt, { encoding: "utf8", mode: 0o600 });
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  await main();
}
