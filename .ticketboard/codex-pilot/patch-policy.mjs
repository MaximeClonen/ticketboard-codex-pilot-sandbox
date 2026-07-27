import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { secretFindings } from "./secret-policy.mjs";
import { validateRuntimeUsage } from "./redact-jsonl.mjs";

function violation(code, detail) {
  return { code, detail };
}

function normalizeDiffPath(rawPath) {
  if (
    typeof rawPath !== "string" ||
    rawPath.length === 0 ||
    rawPath === "/dev/null"
  ) {
    return null;
  }

  if (rawPath.startsWith('"') || /[\t\r\n]/.test(rawPath)) {
    throw new Error(`unsupported quoted or escaped diff path: ${rawPath}`);
  }

  const withoutPrefix =
    rawPath.startsWith("a/") || rawPath.startsWith("b/")
      ? rawPath.slice(2)
      : rawPath;
  const unixPath = withoutPrefix.replaceAll("\\", "/");

  if (
    path.posix.isAbsolute(unixPath) ||
    /^[A-Za-z]:\//.test(unixPath) ||
    unixPath.split("/").includes("..") ||
    unixPath.split("/").includes(".") ||
    unixPath.includes("\0")
  ) {
    throw new Error(`unsafe diff path: ${rawPath}`);
  }

  return unixPath;
}

function extractChangedFiles(patchText) {
  const files = [];
  let current = null;

  const finishFile = () => {
    if (
      current &&
      (!current.oldHeaderSeen ||
        !current.newHeaderSeen ||
        (current.oldPath !== null && current.oldPath !== current.path) ||
        (current.newPath !== null && current.newPath !== current.path))
    ) {
      throw new Error(`mismatched or missing path header: ${current.path}`);
    }
  };

  for (const line of patchText.split(/\r?\n/)) {
    if (line.startsWith("diff --git ")) {
      finishFile();
      const match = /^diff --git ([^\s]+) ([^\s]+)$/.exec(line);
      if (!match) {
        throw new Error(`unsupported diff header: ${line}`);
      }

      const oldPath = normalizeDiffPath(match[1]);
      const newPath = normalizeDiffPath(match[2]);
      if (!oldPath || !newPath || oldPath !== newPath) {
        throw new Error(`renames and path changes are not allowed: ${line}`);
      }
      files.push(newPath);
      current = {
        path: newPath,
        inHunk: false,
        oldHeaderSeen: false,
        newHeaderSeen: false,
        oldPath: undefined,
        newPath: undefined,
      };
      continue;
    }

    if (
      /^(?:rename|copy) (?:from|to) /.test(line) ||
      /^(?:similarity|dissimilarity) index /.test(line)
    ) {
      throw new Error(`rename and copy metadata is forbidden: ${line}`);
    }
    if (!current || current.inHunk) continue;
    if (line.startsWith("@@")) {
      finishFile();
      current.inHunk = true;
      continue;
    }
    if (line.startsWith("--- ")) {
      if (current.oldHeaderSeen) {
        throw new Error(`duplicate old path header: ${line}`);
      }
      current.oldHeaderSeen = true;
      current.oldPath = normalizeDiffPath(line.slice(4));
      continue;
    }
    if (line.startsWith("+++ ")) {
      if (current.newHeaderSeen) {
        throw new Error(`duplicate new path header: ${line}`);
      }
      current.newHeaderSeen = true;
      current.newPath = normalizeDiffPath(line.slice(4));
    }
  }
  finishFile();
  return [...new Set(files)];
}

function isPathAllowed(file, policy) {
  const patchPolicy = policy.patch;
  const basename = path.posix.basename(file);

  if (patchPolicy.forbiddenBasenames.includes(basename)) return false;
  if (
    patchPolicy.forbiddenPrefixes.some(
      (prefix) => file === prefix.slice(0, -1) || file.startsWith(prefix),
    )
  ) {
    return false;
  }
  return patchPolicy.allowedPaths.includes(file);
}

function addedContent(patchText) {
  return patchText
    .split(/\r?\n/)
    .filter(
      (line) =>
        line.startsWith("+") &&
        !line.startsWith("+++") &&
        !line.startsWith("+diff --git "),
    )
    .map((line) => line.slice(1))
    .join("\n");
}

function isCredentialPath(file) {
  const lower = file.toLowerCase();
  const basename = path.posix.basename(lower);
  return (
    lower === ".git/config" ||
    basename === ".env" ||
    basename.startsWith(".env.") ||
    basename.endsWith(".pem") ||
    basename.endsWith(".key") ||
    lower.includes("credential")
  );
}

function patchModeLines(patchText) {
  return (
    patchText.match(
      /^(?:old mode|new mode|new file mode|deleted file mode) \d+$/gm,
    ) ?? []
  );
}

function exactKeys(value, keys) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) ===
      JSON.stringify([...keys].sort())
  );
}

export function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function inspectQuarantinePatch(patchText, policy) {
  const violations = [];
  const byteCount = Buffer.byteLength(patchText, "utf8");
  let files = [];

  if (byteCount === 0 || patchText.trim().length === 0) {
    violations.push(violation("PATCH_EMPTY", "Patch contains no changes."));
  }
  try {
    files = extractChangedFiles(patchText);
  } catch (error) {
    violations.push(violation("PATCH_PATH_INVALID", error.message));
  }
  if (files.length === 0 && byteCount > 0) {
    violations.push(
      violation("PATCH_FORMAT_INVALID", "No supported diff headers found."),
    );
  }
  if (files.length > policy.quarantine.maxChangedFiles) {
    violations.push(
      violation(
        "PATCH_QUARANTINE_FILE_LIMIT",
        "Patch exceeds the artifact quarantine file limit.",
      ),
    );
  }
  if (byteCount > policy.quarantine.maxDiffBytes) {
    violations.push(
      violation(
        "PATCH_QUARANTINE_BYTE_LIMIT",
        "Patch exceeds the artifact quarantine byte limit.",
      ),
    );
  }
  if (files.some(isCredentialPath)) {
    violations.push(
      violation(
        "PATCH_QUARANTINE_CREDENTIAL_PATH",
        "Credential and environment paths cannot cross the artifact boundary.",
      ),
    );
  }
  if (/^(?:GIT binary patch|Binary files .* differ)$/m.test(patchText)) {
    violations.push(
      violation(
        "PATCH_QUARANTINE_BINARY",
        "Binary changes cannot cross the artifact boundary.",
      ),
    );
  }
  for (const code of secretFindings(patchText)) {
    violations.push(
      violation(
        `PATCH_QUARANTINE_SECRET_${code}`,
        "Secret-like patch content cannot cross the artifact boundary.",
      ),
    );
  }
  return {
    allowed: violations.length === 0,
    violations,
    files,
    fileCount: files.length,
    byteCount,
    patchSha256: sha256(patchText),
  };
}

export function inspectPatch(patchText, policy) {
  const violations = [];
  const byteCount = Buffer.byteLength(patchText, "utf8");
  let files = [];

  if (byteCount === 0 || patchText.trim().length === 0) {
    violations.push(violation("PATCH_EMPTY", "Patch contains no changes."));
  }

  try {
    files = extractChangedFiles(patchText);
  } catch (error) {
    violations.push(violation("PATCH_PATH_INVALID", error.message));
  }

  if (files.length === 0 && byteCount > 0) {
    violations.push(
      violation("PATCH_FORMAT_INVALID", "No supported diff headers found."),
    );
  }

  if (files.length > policy.patch.maxChangedFiles) {
    violations.push(
      violation(
        "PATCH_FILE_LIMIT",
        `${files.length} files exceeds ${policy.patch.maxChangedFiles}.`,
      ),
    );
  }

  if (byteCount > policy.patch.maxDiffBytes) {
    violations.push(
      violation(
        "PATCH_BYTE_LIMIT",
        `${byteCount} bytes exceeds ${policy.patch.maxDiffBytes}.`,
      ),
    );
  }

  for (const file of files) {
    if (!isPathAllowed(file, policy)) {
      violations.push(
        violation("PATCH_PATH_FORBIDDEN", `Path is not allowlisted: ${file}`),
      );
    }
  }

  for (const line of patchModeLines(patchText)) {
    if (line.endsWith("120000") && !policy.patch.allowSymlinks) {
      violations.push(
        violation("PATCH_SYMLINK_DENIED", "Symlink changes are denied."),
      );
    } else if (line.endsWith("160000") && !policy.patch.allowSubmodules) {
      violations.push(
        violation("PATCH_SUBMODULE_DENIED", "Submodule changes are denied."),
      );
    } else if (line.endsWith("100755") && !policy.patch.allowExecutableMode) {
      violations.push(
        violation(
          "PATCH_EXECUTABLE_MODE_DENIED",
          "Executable mode changes are denied.",
        ),
      );
    }
  }

  if (
    !policy.patch.allowBinary &&
    /^(?:GIT binary patch|Binary files .* differ)$/m.test(patchText)
  ) {
    violations.push(
      violation("PATCH_BINARY_DENIED", "Binary changes are denied."),
    );
  }

  const additions = addedContent(patchText);
  for (const code of secretFindings(additions)) {
    violations.push(
      violation(`PATCH_SECRET_${code}`, "Secret-like added content detected."),
    );
  }

  return {
    allowed: violations.length === 0,
    violations,
    files,
    fileCount: files.length,
    byteCount,
    patchSha256: sha256(patchText),
  };
}

const MANIFEST_KEYS = [
  "agentRunId",
  "baseSha",
  "byteCount",
  "codex",
  "createdAt",
  "fileCount",
  "files",
  "patchSha256",
  "repositoryId",
  "resultSha256",
  "runtimeUsage",
  "runtimeUsageSha256",
  "version",
].sort();
const CODEX_KEYS = [
  "actionSha",
  "cliVersion",
  "maxRuntimeSeconds",
  "model",
  "network",
  "permissionProfile",
].sort();

function artifactBindingViolations({
  inspection,
  manifest,
  resultText,
  runtimeUsageText,
  runtimeUsage,
  policy,
  expectedAgentRunId,
  expectedBaseSha,
}) {
  const violations = [];
  const exactChecks = [
    ["manifest.version", manifest.version, 1],
    ["manifest.repositoryId", manifest.repositoryId, policy.repository.id],
    ["manifest.agentRunId", manifest.agentRunId, expectedAgentRunId],
    ["manifest.baseSha", manifest.baseSha, expectedBaseSha],
    ["manifest.patchSha256", manifest.patchSha256, inspection.patchSha256],
    ["manifest.fileCount", manifest.fileCount, inspection.fileCount],
    ["manifest.byteCount", manifest.byteCount, inspection.byteCount],
    ["manifest.resultSha256", manifest.resultSha256, sha256(resultText)],
    [
      "manifest.runtimeUsageSha256",
      manifest.runtimeUsageSha256,
      sha256(runtimeUsageText),
    ],
    [
      "manifest.runtimeUsage",
      JSON.stringify(manifest.runtimeUsage),
      JSON.stringify(runtimeUsage),
    ],
    [
      "manifest.codex.actionSha",
      manifest.codex?.actionSha,
      policy.codex.actionSha,
    ],
    [
      "manifest.codex.cliVersion",
      manifest.codex?.cliVersion,
      policy.codex.cliVersion,
    ],
    ["manifest.codex.model", manifest.codex?.model, policy.codex.model],
    [
      "manifest.codex.permissionProfile",
      manifest.codex?.permissionProfile,
      policy.codex.permissionProfile,
    ],
    ["manifest.codex.network", manifest.codex?.network, policy.codex.network],
    [
      "manifest.codex.maxRuntimeSeconds",
      manifest.codex?.maxRuntimeSeconds,
      policy.codex.maxRuntimeSeconds,
    ],
  ];
  for (const [name, actual, expected] of exactChecks) {
    if (actual !== expected) {
      violations.push(
        violation(
          "ARTIFACT_MANIFEST_MISMATCH",
          `${name} does not match its trusted value.`,
        ),
      );
    }
  }
  if (
    !exactKeys(manifest, MANIFEST_KEYS) ||
    !exactKeys(manifest.codex, CODEX_KEYS) ||
    JSON.stringify(manifest.files) !== JSON.stringify(inspection.files) ||
    typeof manifest.agentRunId !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      manifest.agentRunId,
    ) ||
    !/^[0-9a-f]{40}$/.test(manifest.baseSha ?? "") ||
    typeof manifest.createdAt !== "string" ||
    !Number.isFinite(Date.parse(manifest.createdAt))
  ) {
    violations.push(
      violation(
        "ARTIFACT_MANIFEST_INVALID",
        "Manifest shape, files, run ID, base SHA, or timestamp is invalid.",
      ),
    );
  }
  return violations;
}

export function assertCandidateArtifact(options) {
  const inspection = inspectQuarantinePatch(options.patchText, options.policy);
  const violations = [...inspection.violations];
  let runtimeUsage = null;
  try {
    runtimeUsage = validateRuntimeUsage(JSON.parse(options.runtimeUsageText));
  } catch {
    violations.push(
      violation("ARTIFACT_USAGE_INVALID", "Runtime usage is invalid."),
    );
  }
  violations.push(
    ...artifactBindingViolations({
      ...options,
      inspection,
      runtimeUsage,
    }),
  );
  return {
    ...inspection,
    allowed: violations.length === 0,
    violations,
  };
}

export function assertArtifact(options) {
  const candidate = assertCandidateArtifact(options);
  const inspection = inspectPatch(options.patchText, options.policy);
  const violations = [...candidate.violations, ...inspection.violations];
  return {
    ...inspection,
    allowed: violations.length === 0,
    violations,
  };
}

export function classifyArtifact(options) {
  const candidate = assertCandidateArtifact(options);
  if (!candidate.allowed) {
    return {
      outcome: "FAILED",
      reasonCodes: ["ARTIFACT_INTEGRITY_FAILED"],
      inspection: candidate,
    };
  }
  const inspected = inspectPatch(options.patchText, options.policy);
  let structuredResult;
  try {
    structuredResult = JSON.parse(options.resultText);
  } catch {
    return {
      outcome: "FAILED",
      reasonCodes: ["ARTIFACT_RESULT_INVALID"],
      inspection: inspected,
    };
  }
  const reasonCodes = inspected.violations.map(({ code }) => code);
  if (
    JSON.stringify(structuredResult.filesChanged) !==
    JSON.stringify(inspected.files)
  ) {
    reasonCodes.push("RESULT_PATCH_MISMATCH");
  }
  const uniqueReasonCodes = [...new Set(reasonCodes)].sort();
  return {
    outcome: uniqueReasonCodes.length === 0 ? "ALLOWED" : "DENIED",
    reasonCodes: uniqueReasonCodes,
    inspection: inspected,
  };
}

async function loadArtifactArguments(args) {
  const [
    patchPath,
    manifestPath,
    resultPath,
    runtimeUsagePath,
    policyPath,
    expectedAgentRunId,
    expectedBaseSha,
  ] = args;
  if (
    !patchPath ||
    !manifestPath ||
    !resultPath ||
    !runtimeUsagePath ||
    !policyPath ||
    !expectedAgentRunId ||
    !expectedBaseSha
  ) {
    throw new Error(
      "artifact command requires patch, manifest, result, runtime usage, policy, run ID, and base SHA",
    );
  }
  const [patchText, manifest, resultText, runtimeUsageText, policy] =
    await Promise.all([
      readFile(patchPath, "utf8"),
      readFile(manifestPath, "utf8").then(JSON.parse),
      readFile(resultPath, "utf8"),
      readFile(runtimeUsagePath, "utf8"),
      readFile(policyPath, "utf8").then(JSON.parse),
    ]);
  return {
    patchText,
    manifest,
    resultText,
    runtimeUsageText,
    policy,
    expectedAgentRunId,
    expectedBaseSha,
  };
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  if (command === "quarantine") {
    const [patchPath, policyPath] = args;
    if (!patchPath || !policyPath) {
      throw new Error(
        "usage: node patch-policy.mjs quarantine <patch> <policy>",
      );
    }
    const [patchText, policy] = await Promise.all([
      readFile(patchPath, "utf8"),
      readFile(policyPath, "utf8").then(JSON.parse),
    ]);
    const result = inspectQuarantinePatch(patchText, policy);
    process.stdout.write(`${JSON.stringify(result)}\n`);
    if (!result.allowed) process.exitCode = 1;
    return;
  }

  const legacy = command !== "assert" && command !== "classify";
  const options = await loadArtifactArguments(
    legacy ? [command, ...args] : args,
  );
  const result =
    command === "classify"
      ? classifyArtifact(options)
      : assertArtifact(options);
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (command !== "classify" && !result.allowed) process.exitCode = 1;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  await main();
}
