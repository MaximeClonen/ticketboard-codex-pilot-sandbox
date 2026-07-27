import { isUtf8 } from "node:buffer";
import { spawnSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { sha256 } from "./patch-policy.mjs";
import { secretFindings } from "./secret-policy.mjs";

const MANIFEST_KEYS = [
  "agentRunId",
  "archiveSha256",
  "baseSha",
  "byteCount",
  "createdAt",
  "repositoryId",
  "treeSha",
  "version",
  "workflowRunAttempt",
  "workflowRunId",
].sort();

function assertRunCoordinates({
  agentRunId,
  baseSha,
  workflowRunId,
  workflowRunAttempt,
}) {
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      agentRunId,
    )
  ) {
    throw new Error("agent run ID must be a UUID");
  }
  if (!/^[0-9a-f]{40}$/.test(baseSha)) {
    throw new Error("base SHA must be a lowercase full commit SHA");
  }
  if (!/^[1-9][0-9]*$/.test(String(workflowRunId))) {
    throw new Error("workflow run ID is invalid");
  }
  const attempt = Number(workflowRunAttempt);
  if (!Number.isSafeInteger(attempt) || attempt < 1 || attempt > 100) {
    throw new Error("workflow run attempt is invalid");
  }
}

function exactKeys(value, keys) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify(keys)
  );
}

function git(args, { cwd, encoding = "utf8", maxBuffer = 64 * 1024 * 1024 }) {
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
    cwd,
    encoding,
    env: {
      PATH: process.env.PATH,
      SystemRoot: process.env.SystemRoot,
      HOME: process.env.HOME,
      LANG: "C.UTF-8",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_SYSTEM: "/dev/null",
      GIT_TERMINAL_PROMPT: "0",
    },
    maxBuffer,
    windowsHide: true,
  });
  if (result.status !== 0) {
    throw new Error(`trusted source snapshot git command failed: ${args[0]}`);
  }
  return result.stdout;
}

export function scanTrackedSource(repositoryPath, baseSha, policy) {
  const sourcePolicy = policy?.source;
  if (
    sourcePolicy?.maxTrackedFiles !== 500 ||
    sourcePolicy?.maxTextFileBytes !== 1_048_576 ||
    sourcePolicy?.maxTotalBytes !== 8_388_608 ||
    sourcePolicy?.allowBinary !== false
  ) {
    throw new Error("trusted source scan policy is invalid");
  }
  const listing = git(
    ["ls-tree", "-r", "-z", "--long", "--full-tree", baseSha],
    { cwd: repositoryPath, encoding: "buffer" },
  )
    .toString("utf8")
    .split("\0")
    .filter(Boolean);
  if (listing.length === 0 || listing.length > sourcePolicy.maxTrackedFiles) {
    throw new Error("tracked source exceeds its file-count bound");
  }

  let totalBytes = 0;
  const blobs = [];
  for (const entry of listing) {
    const tab = entry.indexOf("\t");
    const metadata = tab < 0 ? "" : entry.slice(0, tab);
    const file = tab < 0 ? "" : entry.slice(tab + 1);
    const match = /^(100644|100755) blob ([0-9a-f]{40}) +([0-9]+)$/.exec(
      metadata,
    );
    if (
      !match ||
      file.length === 0 ||
      /[\u0000-\u001f\u007f]/.test(file) ||
      path.posix.isAbsolute(file) ||
      file.split("/").some((segment) => segment === "." || segment === "..")
    ) {
      throw new Error("tracked source contains an unsupported tree entry");
    }
    const byteCount = Number(match[3]);
    if (
      !Number.isSafeInteger(byteCount) ||
      byteCount < 0 ||
      byteCount > sourcePolicy.maxTextFileBytes
    ) {
      throw new Error("tracked source exceeds its per-file byte bound");
    }
    totalBytes += byteCount;
    if (totalBytes > sourcePolicy.maxTotalBytes) {
      throw new Error("tracked source exceeds its total byte bound");
    }
    blobs.push({ objectId: match[2], byteCount });
  }

  for (const blob of blobs) {
    const content = git(["cat-file", "blob", blob.objectId], {
      cwd: repositoryPath,
      encoding: "buffer",
      maxBuffer: sourcePolicy.maxTextFileBytes + 1024,
    });
    if (
      content.length !== blob.byteCount ||
      content.includes(0) ||
      !isUtf8(content)
    ) {
      throw new Error("tracked source binary content is not permitted");
    }
    if (secretFindings(content.toString("utf8")).length > 0) {
      throw new Error("TRACKED_SOURCE_SECRET_DENIED");
    }
  }
  return { fileCount: blobs.length, byteCount: totalBytes };
}

export function buildSourceManifest({
  archive,
  agentRunId,
  repositoryId,
  baseSha,
  treeSha,
  workflowRunId,
  workflowRunAttempt,
  timestamp,
}) {
  assertRunCoordinates({
    agentRunId,
    baseSha,
    workflowRunId,
    workflowRunAttempt,
  });
  if (!Buffer.isBuffer(archive) || archive.length === 0) {
    throw new Error("source archive is empty");
  }
  if (!/^[0-9a-f]{40}$/.test(treeSha)) {
    throw new Error("source tree SHA is invalid");
  }
  return {
    version: 1,
    agentRunId,
    repositoryId,
    baseSha,
    treeSha,
    workflowRunId: String(workflowRunId),
    workflowRunAttempt: Number(workflowRunAttempt),
    archiveSha256: sha256(archive),
    byteCount: archive.length,
    createdAt: timestamp,
  };
}

export function verifySourceArtifact({
  archive,
  manifest,
  policy,
  expectedAgentRunId,
  expectedBaseSha,
  expectedWorkflowRunId,
  expectedWorkflowRunAttempt,
}) {
  assertRunCoordinates({
    agentRunId: expectedAgentRunId,
    baseSha: expectedBaseSha,
    workflowRunId: expectedWorkflowRunId,
    workflowRunAttempt: expectedWorkflowRunAttempt,
  });
  if (!exactKeys(manifest, MANIFEST_KEYS)) {
    throw new Error("source manifest is not closed");
  }
  const exact = [
    [manifest.version, 1],
    [manifest.agentRunId, expectedAgentRunId],
    [manifest.repositoryId, policy.repository.id],
    [manifest.baseSha, expectedBaseSha],
    [manifest.workflowRunId, String(expectedWorkflowRunId)],
    [manifest.workflowRunAttempt, Number(expectedWorkflowRunAttempt)],
    [manifest.archiveSha256, sha256(archive)],
    [manifest.byteCount, archive.length],
  ];
  if (
    exact.some(([actual, expected]) => actual !== expected) ||
    !/^[0-9a-f]{64}$/.test(manifest.archiveSha256) ||
    !/^[0-9a-f]{40}$/.test(manifest.treeSha) ||
    typeof manifest.createdAt !== "string" ||
    !Number.isFinite(Date.parse(manifest.createdAt))
  ) {
    throw new Error("source artifact failed exact run/base/hash binding");
  }
  return {
    verified: true,
    archiveSha256: manifest.archiveSha256,
    byteCount: manifest.byteCount,
  };
}

async function create([
  repositoryPath,
  baseSha,
  agentRunId,
  workflowRunId,
  workflowRunAttempt,
  policyPath,
  archivePath,
  manifestPath,
]) {
  if (
    !repositoryPath ||
    !baseSha ||
    !agentRunId ||
    !workflowRunId ||
    !workflowRunAttempt ||
    !policyPath ||
    !archivePath ||
    !manifestPath
  ) {
    throw new Error(
      "usage: source-snapshot.mjs create <repo> <base-sha> <agent-run-id> <workflow-run-id> <workflow-run-attempt> <policy> <archive-out> <manifest-out>",
    );
  }
  assertRunCoordinates({
    agentRunId,
    baseSha,
    workflowRunId,
    workflowRunAttempt,
  });
  const policy = JSON.parse(await readFile(policyPath, "utf8"));
  const head = git(["rev-parse", "HEAD"], { cwd: repositoryPath }).trim();
  const status = git(["status", "--short"], { cwd: repositoryPath }).trim();
  if (head !== baseSha || status.length > 0) {
    throw new Error("source checkout is not the clean exact approved base");
  }

  scanTrackedSource(repositoryPath, baseSha, policy);

  const treeSha = git(["rev-parse", `${baseSha}^{tree}`], {
    cwd: repositoryPath,
  }).trim();
  const archive = git(["archive", "--format=tar", baseSha], {
    cwd: repositoryPath,
    encoding: "buffer",
  });
  const manifest = buildSourceManifest({
    archive,
    agentRunId,
    repositoryId: policy.repository.id,
    baseSha,
    treeSha,
    workflowRunId,
    workflowRunAttempt,
    timestamp: new Date().toISOString(),
  });
  await Promise.all([
    writeFile(archivePath, archive, { mode: 0o600 }),
    writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600,
    }),
  ]);
}

async function verify([
  archivePath,
  manifestPath,
  policyPath,
  agentRunId,
  baseSha,
  workflowRunId,
  workflowRunAttempt,
]) {
  if (
    !archivePath ||
    !manifestPath ||
    !policyPath ||
    !agentRunId ||
    !baseSha ||
    !workflowRunId ||
    !workflowRunAttempt
  ) {
    throw new Error(
      "usage: source-snapshot.mjs verify <archive> <manifest> <policy> <agent-run-id> <base-sha> <workflow-run-id> <workflow-run-attempt>",
    );
  }
  const [archive, manifest, policy] = await Promise.all([
    readFile(archivePath),
    readFile(manifestPath, "utf8").then(JSON.parse),
    readFile(policyPath, "utf8").then(JSON.parse),
  ]);
  const result = verifySourceArtifact({
    archive,
    manifest,
    policy,
    expectedAgentRunId: agentRunId,
    expectedBaseSha: baseSha,
    expectedWorkflowRunId: workflowRunId,
    expectedWorkflowRunAttempt: workflowRunAttempt,
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  if (command === "create") return create(args);
  if (command === "verify") return verify(args);
  throw new Error("source-snapshot.mjs command must be create or verify");
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  await main();
}
