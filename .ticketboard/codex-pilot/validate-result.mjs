import { readFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { secretFindings } from "./secret-policy.mjs";

const ROOT_KEYS = [
  "acceptanceCriteria",
  "filesChanged",
  "followUpCodes",
  "outcome",
  "recommendedRunStatus",
  "recommendedWorkItemTransition",
  "riskCodes",
  "summary",
  "tests",
  "usage",
].sort();
const TEST_CODES = new Set([
  "FORMAT_CHECK",
  "LINT",
  "TYPECHECK",
  "UNIT_TESTS",
  "INTEGRATION_TESTS",
  "E2E",
  "BUILD",
  "VERIFY",
]);

function exactKeys(value, keys) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) ===
      JSON.stringify([...keys].sort())
  );
}

function boundedString(value, maxLength, minLength = 0) {
  return (
    typeof value === "string" &&
    value.length >= minLength &&
    value.length <= maxLength &&
    !/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value)
  );
}

function boundedCode(value) {
  return boundedString(value, 64, 1) && /^[A-Z][A-Z0-9_]{0,63}$/.test(value);
}

function unique(values) {
  return new Set(values).size === values.length;
}

export function validateStructuredResult(value, policy) {
  const errors = [];
  const add = (message) => errors.push(message);

  if (!exactKeys(value, ROOT_KEYS)) {
    add("result must have only the closed root schema keys");
    return { valid: false, errors };
  }

  if (!["PATCH_READY", "BLOCKED", "NO_CHANGE"].includes(value.outcome)) {
    add("outcome is invalid");
  }
  if (!boundedString(value.summary, 1000, 1)) add("summary is invalid");
  if (secretFindings(value).length > 0) {
    add("result contains secret-like content");
  }

  if (
    !Array.isArray(value.filesChanged) ||
    value.filesChanged.length > policy.patch.maxChangedFiles ||
    !unique(value.filesChanged) ||
    value.filesChanged.some(
      (file) =>
        !boundedString(file, 160, 1) ||
        !policy.patch.allowedPaths.includes(file),
    )
  ) {
    add("filesChanged is invalid");
  }

  if (
    !Array.isArray(value.tests) ||
    value.tests.length > 8 ||
    value.tests.some(
      (test) =>
        !exactKeys(test, ["code", "status", "summary"]) ||
        !TEST_CODES.has(test.code) ||
        !["PASSED", "FAILED", "NOT_RUN"].includes(test.status) ||
        !boundedString(test.summary, 240),
    )
  ) {
    add("tests is invalid");
  }

  if (
    !Array.isArray(value.acceptanceCriteria) ||
    value.acceptanceCriteria.length > 16 ||
    value.acceptanceCriteria.some(
      (criterion) =>
        !exactKeys(criterion, ["criterion", "status", "evidence"]) ||
        !boundedString(criterion.criterion, 240, 1) ||
        !["MET", "NOT_MET", "NOT_VERIFIED"].includes(criterion.status) ||
        !boundedString(criterion.evidence, 400),
    )
  ) {
    add("acceptanceCriteria is invalid");
  }

  for (const [name, codes] of [
    ["riskCodes", value.riskCodes],
    ["followUpCodes", value.followUpCodes],
  ]) {
    if (
      !Array.isArray(codes) ||
      codes.length > 12 ||
      !unique(codes) ||
      codes.some((code) => !boundedCode(code))
    ) {
      add(`${name} is invalid`);
    }
  }

  if (
    !["REVIEW_REQUIRED", "BLOCKED", "FAILED"].includes(
      value.recommendedRunStatus,
    )
  ) {
    add("recommendedRunStatus is invalid");
  }
  if (
    value.outcome === "PATCH_READY" &&
    value.recommendedRunStatus !== "REVIEW_REQUIRED"
  ) {
    add("PATCH_READY must recommend REVIEW_REQUIRED");
  }
  if (value.recommendedWorkItemTransition !== "NONE") {
    add("recommendedWorkItemTransition must be NONE");
  }
  if (
    !exactKeys(value.usage, [
      "cachedInputTokens",
      "inputTokens",
      "outputTokens",
    ]) ||
    !Number.isSafeInteger(value.usage.inputTokens) ||
    value.usage.inputTokens < 0 ||
    value.usage.inputTokens > 1_000_000 ||
    !Number.isSafeInteger(value.usage.cachedInputTokens) ||
    value.usage.cachedInputTokens < 0 ||
    value.usage.cachedInputTokens > value.usage.inputTokens ||
    !Number.isSafeInteger(value.usage.outputTokens) ||
    value.usage.outputTokens < 0 ||
    value.usage.outputTokens > 1_000_000
  ) {
    add("usage is invalid");
  }

  return { valid: errors.length === 0, errors };
}

async function main() {
  const [resultPath, policyPath] = process.argv.slice(2);
  if (!resultPath || !policyPath) {
    throw new Error(
      "usage: node validate-result.mjs <structured-result> <policy>",
    );
  }
  const [resultText, policyText] = await Promise.all([
    readFile(resultPath, "utf8"),
    readFile(policyPath, "utf8"),
  ]);
  const validation = validateStructuredResult(
    JSON.parse(resultText),
    JSON.parse(policyText),
  );
  process.stdout.write(`${JSON.stringify(validation)}\n`);
  if (!validation.valid) process.exitCode = 1;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  await main();
}
