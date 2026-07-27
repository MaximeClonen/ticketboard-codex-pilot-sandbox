import { spawnSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { inspectQuarantinePatch, sha256 } from "./patch-policy.mjs";
import { validateRuntimeUsage } from "./redact-jsonl.mjs";
import { validateStructuredResult } from "./validate-result.mjs";

function runGit(args, options = {}) {
  const hardenedArgs = [
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "diff.external=",
    ...args,
  ];
  const result = spawnSync("git", hardenedArgs, {
    cwd: options.cwd,
    encoding: options.encoding ?? "utf8",
    env: {
      PATH: process.env.PATH,
      SystemRoot: process.env.SystemRoot,
      HOME: process.env.HOME,
      LANG: "C.UTF-8",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_SYSTEM: "/dev/null",
      GIT_TERMINAL_PROMPT: "0",
    },
    maxBuffer: 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error(`trusted git command failed: git ${args[0]}`);
  }
  return result.stdout;
}

export function assertUsageMatchesRuntime(structuredResult, runtimeUsage) {
  const modelUsage = structuredResult?.usage;
  if (
    modelUsage?.inputTokens !== runtimeUsage.inputTokens ||
    modelUsage?.cachedInputTokens !== runtimeUsage.cachedInputTokens ||
    modelUsage?.outputTokens !== runtimeUsage.outputTokens
  ) {
    throw new Error(
      "Codex structured result usage does not match authoritative runtime usage",
    );
  }
}
export function buildArtifactManifest({
  agentRunId,
  repositoryId,
  baseSha,
  patchText,
  resultText,
  runtimeUsageText,
  runtimeUsage,
  inspection,
  policy,
  timestamp,
}) {
  return {
    version: 1,
    agentRunId,
    repositoryId,
    baseSha,
    patchSha256: sha256(patchText),
    files: inspection.files,
    fileCount: inspection.fileCount,
    byteCount: inspection.byteCount,
    resultSha256: sha256(resultText),
    runtimeUsageSha256: sha256(runtimeUsageText),
    runtimeUsage: validateRuntimeUsage(runtimeUsage),
    codex: {
      actionSha: policy.codex.actionSha,
      cliVersion: policy.codex.cliVersion,
      model: policy.codex.model,
      permissionProfile: policy.codex.permissionProfile,
      network: policy.codex.network,
      maxRuntimeSeconds: policy.codex.maxRuntimeSeconds,
    },
    createdAt: timestamp,
  };
}

async function main() {
  const [
    repositoryPath,
    baseSha,
    agentRunId,
    resultPath,
    runtimeUsagePath,
    policyPath,
    patchOutputPath,
    manifestOutputPath,
  ] = process.argv.slice(2);
  if (
    !repositoryPath ||
    !baseSha ||
    !agentRunId ||
    !resultPath ||
    !runtimeUsagePath ||
    !policyPath ||
    !patchOutputPath ||
    !manifestOutputPath
  ) {
    throw new Error(
      "usage: node create-patch.mjs <repo> <base-sha> <run-id> <result> <runtime-usage> <policy> <patch-out> <manifest-out>",
    );
  }
  if (!/^[0-9a-f]{40}$/.test(baseSha)) {
    throw new Error("base SHA must be a lowercase full commit SHA");
  }
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      agentRunId,
    )
  ) {
    throw new Error("agent run ID must be a UUID");
  }

  const [policyText, resultText, runtimeUsageText] = await Promise.all([
    readFile(policyPath, "utf8"),
    readFile(resultPath, "utf8"),
    readFile(runtimeUsagePath, "utf8"),
  ]);
  const policy = JSON.parse(policyText);
  const structuredResult = JSON.parse(resultText);
  const runtimeUsage = validateRuntimeUsage(JSON.parse(runtimeUsageText));
  const resultValidation = validateStructuredResult(structuredResult, policy);
  if (!resultValidation.valid) {
    throw new Error("Codex structured result failed closed-schema validation");
  }
  assertUsageMatchesRuntime(structuredResult, runtimeUsage);

  const head = runGit(["rev-parse", "HEAD"], {
    cwd: repositoryPath,
  }).trim();
  if (head !== baseSha)
    throw new Error("checkout is not at the exact base SHA");

  const untracked = runGit(
    ["ls-files", "--others", "--exclude-standard", "-z"],
    {
      cwd: repositoryPath,
      encoding: "buffer",
    },
  )
    .toString("utf8")
    .split("\0")
    .filter(Boolean);
  for (const file of untracked) {
    if (!policy.patch.allowedPaths.includes(file.replaceAll("\\", "/"))) {
      throw new Error(`untracked path is not allowlisted: ${file}`);
    }
  }
  if (untracked.length > 0) {
    runGit(["add", "-N", "--", ...untracked], { cwd: repositoryPath });
  }

  const patchText = runGit(
    ["diff", "--binary", "--no-ext-diff", "--no-textconv", baseSha, "--"],
    {
      cwd: repositoryPath,
    },
  );
  const inspection = inspectQuarantinePatch(patchText, policy);
  if (!inspection.allowed) {
    throw new Error(
      `patch quarantine denied: ${inspection.violations
        .map(({ code }) => code)
        .join(",")}`,
    );
  }
  if (
    structuredResult.outcome !== "PATCH_READY" ||
    structuredResult.recommendedRunStatus !== "REVIEW_REQUIRED" ||
    structuredResult.recommendedWorkItemTransition !== "NONE"
  ) {
    throw new Error("structured result cannot register a patch candidate");
  }

  const manifest = buildArtifactManifest({
    agentRunId,
    repositoryId: policy.repository.id,
    baseSha,
    patchText,
    resultText,
    runtimeUsageText,
    runtimeUsage,
    inspection,
    policy,
    timestamp: new Date().toISOString(),
  });
  await Promise.all([
    writeFile(patchOutputPath, patchText, { encoding: "utf8", mode: 0o600 }),
    writeFile(manifestOutputPath, `${JSON.stringify(manifest, null, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600,
    }),
  ]);
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  await main();
}
