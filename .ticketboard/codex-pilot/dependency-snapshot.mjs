import { createHash } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  readlink,
  realpath,
  symlink,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const MAGIC = Buffer.from("TICKETBOARD_NPM_DEPENDENCIES_V1\n", "utf8");
const MAX_ENTRIES = 25_000;
const MAX_FILE_BYTES = 16 * 1024 * 1024;
const MAX_TOTAL_BYTES = 256 * 1024 * 1024;
const MAX_ARCHIVE_BYTES = 320 * 1024 * 1024;
const MAX_HEADER_BYTES = 4_096;
const FORBIDDEN_CONFIG_BASENAMES = new Set([
  ".netrc",
  ".npmrc",
  ".yarnrc",
  "_auth",
  "credentials",
  "npm-debug.log",
  "settings.xml",
]);

function exactKeys(value, expected) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) ===
      JSON.stringify([...expected].sort())
  );
}

export function validateRunCoordinates(
  agentRunId,
  baseSha,
  workflowRunId,
  runAttempt,
) {
  if (
    !/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(
      agentRunId,
    ) ||
    !/^[0-9a-f]{40}$/.test(baseSha) ||
    !/^[1-9][0-9]*$/.test(workflowRunId) ||
    !/^[1-9][0-9]*$/.test(runAttempt)
  ) {
    throw new Error("dependency snapshot coordinates are invalid");
  }
  const workflowRunNumber = Number(workflowRunId);
  const attemptNumber = Number(runAttempt);
  if (
    !Number.isSafeInteger(workflowRunNumber) ||
    workflowRunNumber < 1 ||
    String(workflowRunNumber) !== workflowRunId ||
    !Number.isSafeInteger(attemptNumber) ||
    attemptNumber < 1 ||
    attemptNumber > 100 ||
    String(attemptNumber) !== runAttempt
  ) {
    throw new Error("dependency snapshot coordinates are invalid");
  }
}

function validateRuntimeVersion(nodeVersion, npmVersion) {
  if (
    !/^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/.test(nodeVersion) ||
    !/^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/.test(npmVersion)
  ) {
    throw new Error("dependency runtime version is invalid");
  }
}

function safeRelativePath(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 512 &&
    value === value.replaceAll("\\", "/") &&
    !path.posix.isAbsolute(value) &&
    !/[\u0000-\u001f\u007f]/.test(value) &&
    value.split("/").every((segment) => segment !== "." && segment !== "..")
  );
}

function digest(value) {
  return createHash("sha256").update(value).digest("hex");
}

export async function validateDependencySource(repositoryRoot) {
  const packageJsonPath = path.join(repositoryRoot, "package.json");
  const packageLockPath = path.join(repositoryRoot, "package-lock.json");
  const [packageJsonBytes, packageLockBytes] = await Promise.all([
    readFile(packageJsonPath),
    readFile(packageLockPath),
  ]);
  const packageJson = JSON.parse(packageJsonBytes.toString("utf8"));
  const packageLock = JSON.parse(packageLockBytes.toString("utf8"));
  if (
    packageJson === null ||
    typeof packageJson !== "object" ||
    Array.isArray(packageJson) ||
    "workspaces" in packageJson ||
    packageLock?.lockfileVersion !== 3 ||
    packageLock?.packages === null ||
    typeof packageLock?.packages !== "object" ||
    Array.isArray(packageLock.packages) ||
    packageLock.packages[""] === null ||
    typeof packageLock.packages[""] !== "object"
  ) {
    throw new Error(
      "dependency source must be a non-workspace npm lockfile v3 project",
    );
  }

  for (const [packagePath, entry] of Object.entries(packageLock.packages)) {
    if (packagePath === "") continue;
    if (
      !packagePath.startsWith("node_modules/") ||
      entry === null ||
      typeof entry !== "object" ||
      Array.isArray(entry) ||
      entry.link === true ||
      typeof entry.resolved !== "string" ||
      !/^sha512-[A-Za-z0-9+/]+={0,2}$/.test(entry.integrity ?? "")
    ) {
      throw new Error(
        "dependency lockfile contains an unsupported package source",
      );
    }
    let resolved;
    try {
      resolved = new URL(entry.resolved);
    } catch {
      throw new Error("dependency lockfile contains an invalid resolved URL");
    }
    if (
      resolved.protocol !== "https:" ||
      resolved.hostname !== "registry.npmjs.org" ||
      resolved.port !== "" ||
      resolved.username !== "" ||
      resolved.password !== "" ||
      resolved.search !== "" ||
      resolved.hash !== ""
    ) {
      throw new Error(
        "dependency lockfile contains a non-reviewed registry URL",
      );
    }
  }

  async function rejectConfiguration(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (entry.name === ".git" || entry.name === "node_modules") continue;
      if (FORBIDDEN_CONFIG_BASENAMES.has(entry.name.toLowerCase())) {
        throw new Error(
          "dependency source contains package-manager authentication config",
        );
      }
      if (entry.isSymbolicLink()) {
        throw new Error(
          "dependency source contains a symlink before installation",
        );
      }
      if (entry.isDirectory()) {
        await rejectConfiguration(path.join(directory, entry.name));
      }
    }
  }
  await rejectConfiguration(repositoryRoot);

  return {
    packageJsonSha256: digest(packageJsonBytes),
    packageLockSha256: digest(packageLockBytes),
    lockfileVersion: packageLock.lockfileVersion,
  };
}

function assertSafeArtifactPath(root, target) {
  const resolvedRoot = path.resolve(root);
  const resolvedTarget = path.resolve(target);
  if (
    resolvedTarget === resolvedRoot ||
    !resolvedTarget.startsWith(`${resolvedRoot}${path.sep}`)
  ) {
    throw new Error("dependency artifact path escaped its root");
  }
  return resolvedTarget;
}

async function dependencyTree(repositoryRoot) {
  const nodeModulesRoot = path.join(repositoryRoot, "node_modules");
  const rootStat = await lstat(nodeModulesRoot);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    throw new Error("npm ci did not produce a regular node_modules directory");
  }
  const rootRealPath = await realpath(nodeModulesRoot);
  const entries = [];
  let totalBytes = 0;

  async function visit(directory, relative = "") {
    for (const directoryEntry of await readdir(directory, {
      withFileTypes: true,
    })) {
      const relativePath = relative
        ? `${relative}/${directoryEntry.name}`
        : directoryEntry.name;
      if (!safeRelativePath(relativePath)) {
        throw new Error("dependency tree contains an unsafe path");
      }
      if (FORBIDDEN_CONFIG_BASENAMES.has(directoryEntry.name.toLowerCase())) {
        throw new Error(
          "dependency tree contains package-manager authentication config",
        );
      }
      const absolutePath = assertSafeArtifactPath(
        nodeModulesRoot,
        path.join(nodeModulesRoot, ...relativePath.split("/")),
      );
      const stat = await lstat(absolutePath);
      const mode = stat.mode & 0o777;
      if (stat.isDirectory() && !stat.isSymbolicLink()) {
        entries.push({ path: relativePath, type: "directory", mode });
        await visit(absolutePath, relativePath);
      } else if (stat.isFile() && !stat.isSymbolicLink()) {
        if (stat.size > MAX_FILE_BYTES) {
          throw new Error("dependency tree contains an oversized file");
        }
        const content = await readFile(absolutePath);
        totalBytes += content.length;
        entries.push({
          path: relativePath,
          type: "file",
          mode,
          size: content.length,
          sha256: digest(content),
        });
      } else if (stat.isSymbolicLink()) {
        const target = await readlink(absolutePath);
        if (
          path.isAbsolute(target) ||
          /[\u0000-\u001f\u007f]/.test(target) ||
          target.length === 0 ||
          target.length > 512
        ) {
          throw new Error("dependency tree contains an unsafe symlink target");
        }
        const finalTarget = await realpath(absolutePath);
        if (
          finalTarget !== rootRealPath &&
          !finalTarget.startsWith(`${rootRealPath}${path.sep}`)
        ) {
          throw new Error("dependency tree symlink escapes node_modules");
        }
        entries.push({ path: relativePath, type: "symlink", mode, target });
      } else {
        throw new Error("dependency tree contains a non-regular entry");
      }
      if (entries.length > MAX_ENTRIES || totalBytes > MAX_TOTAL_BYTES) {
        throw new Error("dependency tree exceeds its reviewed bounds");
      }
    }
  }
  await visit(nodeModulesRoot);
  entries.sort((left, right) => left.path.localeCompare(right.path, "en"));
  return { entries, totalBytes, nodeModulesRoot };
}

function validateTreeEntry(entry) {
  if (
    !safeRelativePath(entry?.path) ||
    !Number.isInteger(entry?.mode) ||
    entry.mode < 0 ||
    entry.mode > 0o777
  ) {
    throw new Error("dependency manifest tree entry is invalid");
  }
  if (
    entry.type === "directory" &&
    exactKeys(entry, ["mode", "path", "type"])
  ) {
    return;
  }
  if (
    entry.type === "file" &&
    exactKeys(entry, ["mode", "path", "sha256", "size", "type"]) &&
    Number.isInteger(entry.size) &&
    entry.size >= 0 &&
    entry.size <= MAX_FILE_BYTES &&
    /^[0-9a-f]{64}$/.test(entry.sha256)
  ) {
    return;
  }
  if (
    entry.type === "symlink" &&
    exactKeys(entry, ["mode", "path", "target", "type"]) &&
    typeof entry.target === "string" &&
    entry.target.length > 0 &&
    entry.target.length <= 512 &&
    !path.isAbsolute(entry.target) &&
    !/[\u0000-\u001f\u007f]/.test(entry.target)
  ) {
    return;
  }
  throw new Error("dependency manifest tree entry is invalid");
}

export function validateDependencyManifest(
  manifest,
  { agentRunId, baseSha, workflowRunId, runAttempt, npmVersion },
) {
  validateRunCoordinates(agentRunId, baseSha, workflowRunId, runAttempt);
  validateRuntimeVersion(process.version, npmVersion);
  if (
    !exactKeys(manifest, [
      "agentRunId",
      "archiveBytes",
      "archiveSha256",
      "baseSha",
      "fileCount",
      "format",
      "lockfileVersion",
      "nodeVersion",
      "npmVersion",
      "packageJsonSha256",
      "packageLockSha256",
      "runAttempt",
      "totalBytes",
      "tree",
      "workflowRunId",
    ]) ||
    manifest.format !== "IMMUTABLE_NPM_DEPENDENCIES_V1" ||
    manifest.agentRunId !== agentRunId ||
    manifest.baseSha !== baseSha ||
    manifest.workflowRunId !== workflowRunId ||
    manifest.runAttempt !== Number(runAttempt) ||
    manifest.nodeVersion !== process.version ||
    manifest.npmVersion !== npmVersion ||
    manifest.lockfileVersion !== 3 ||
    !Number.isInteger(manifest.archiveBytes) ||
    manifest.archiveBytes <= MAGIC.length ||
    manifest.archiveBytes > MAX_ARCHIVE_BYTES ||
    !/^[0-9a-f]{64}$/.test(manifest.archiveSha256) ||
    !/^[0-9a-f]{64}$/.test(manifest.packageJsonSha256) ||
    !/^[0-9a-f]{64}$/.test(manifest.packageLockSha256) ||
    !Array.isArray(manifest.tree) ||
    manifest.tree.length === 0 ||
    manifest.tree.length > MAX_ENTRIES ||
    manifest.fileCount !== manifest.tree.length ||
    !Number.isInteger(manifest.totalBytes) ||
    manifest.totalBytes < 0 ||
    manifest.totalBytes > MAX_TOTAL_BYTES
  ) {
    throw new Error("dependency manifest is invalid");
  }
  let previousPath = "";
  let totalBytes = 0;
  for (const entry of manifest.tree) {
    validateTreeEntry(entry);
    if (
      previousPath !== "" &&
      previousPath.localeCompare(entry.path, "en") >= 0
    ) {
      throw new Error("dependency manifest paths are not unique and sorted");
    }
    previousPath = entry.path;
    if (entry.type === "file") totalBytes += entry.size;
  }
  if (totalBytes !== manifest.totalBytes) {
    throw new Error("dependency manifest byte count is invalid");
  }
  return manifest;
}

async function writeRecord(handle, header, content = null) {
  const headerBytes = Buffer.from(JSON.stringify(header), "utf8");
  if (headerBytes.length === 0 || headerBytes.length > MAX_HEADER_BYTES) {
    throw new Error("dependency archive header is invalid");
  }
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(headerBytes.length);
  await handle.write(prefix);
  await handle.write(headerBytes);
  if (content !== null) await handle.write(content);
}

export async function createDependencySnapshot({
  repositoryRoot,
  agentRunId,
  baseSha,
  workflowRunId,
  runAttempt,
  npmVersion,
  archivePath,
  manifestPath,
}) {
  validateRunCoordinates(agentRunId, baseSha, workflowRunId, runAttempt);
  validateRuntimeVersion(process.version, npmVersion);
  const source = await validateDependencySource(repositoryRoot);
  const { entries, totalBytes, nodeModulesRoot } =
    await dependencyTree(repositoryRoot);
  await mkdir(path.dirname(archivePath), { recursive: true, mode: 0o700 });
  const archive = await open(archivePath, "w", 0o600);
  try {
    await archive.write(MAGIC);
    for (const entry of entries) {
      const content =
        entry.type === "file"
          ? await readFile(path.join(nodeModulesRoot, ...entry.path.split("/")))
          : null;
      await writeRecord(archive, entry, content);
    }
    await archive.write(Buffer.alloc(4));
  } finally {
    await archive.close();
  }
  const archiveBytes = await readFile(archivePath);
  if (archiveBytes.length > MAX_ARCHIVE_BYTES) {
    throw new Error("dependency archive exceeds its reviewed bound");
  }
  const manifest = {
    format: "IMMUTABLE_NPM_DEPENDENCIES_V1",
    agentRunId,
    baseSha,
    workflowRunId,
    runAttempt: Number(runAttempt),
    nodeVersion: process.version,
    npmVersion,
    lockfileVersion: source.lockfileVersion,
    packageJsonSha256: source.packageJsonSha256,
    packageLockSha256: source.packageLockSha256,
    archiveSha256: digest(archiveBytes),
    archiveBytes: archiveBytes.length,
    fileCount: entries.length,
    totalBytes,
    tree: entries,
  };
  validateDependencyManifest(manifest, {
    agentRunId,
    baseSha,
    workflowRunId,
    runAttempt,
    npmVersion,
  });
  await mkdir(path.dirname(manifestPath), { recursive: true, mode: 0o700 });
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  return manifest;
}

async function readExact(handle, length, position) {
  const buffer = Buffer.alloc(length);
  let offset = 0;
  while (offset < length) {
    const { bytesRead } = await handle.read(
      buffer,
      offset,
      length - offset,
      position + offset,
    );
    if (bytesRead === 0) {
      throw new Error("dependency archive ended unexpectedly");
    }
    offset += bytesRead;
  }
  return buffer;
}

export async function verifyDependencySnapshot({
  repositoryRoot,
  agentRunId,
  baseSha,
  workflowRunId,
  runAttempt,
  npmVersion,
  archivePath,
  manifestPath,
}) {
  const manifest = validateDependencyManifest(
    JSON.parse(await readFile(manifestPath, "utf8")),
    { agentRunId, baseSha, workflowRunId, runAttempt, npmVersion },
  );
  const source = await validateDependencySource(repositoryRoot);
  if (
    source.packageJsonSha256 !== manifest.packageJsonSha256 ||
    source.packageLockSha256 !== manifest.packageLockSha256 ||
    source.lockfileVersion !== manifest.lockfileVersion
  ) {
    throw new Error(
      "dependency artifact does not match the exact source lockfile",
    );
  }
  const archiveStat = await lstat(archivePath);
  if (
    !archiveStat.isFile() ||
    archiveStat.isSymbolicLink() ||
    archiveStat.size !== manifest.archiveBytes ||
    archiveStat.size > MAX_ARCHIVE_BYTES
  ) {
    throw new Error("dependency archive file is invalid");
  }
  const archiveBytes = await readFile(archivePath);
  if (digest(archiveBytes) !== manifest.archiveSha256) {
    throw new Error("dependency archive digest mismatch");
  }

  const nodeModulesRoot = path.join(repositoryRoot, "node_modules");
  try {
    await lstat(nodeModulesRoot);
    throw new Error("dependency target node_modules already exists");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  await mkdir(nodeModulesRoot, { mode: 0o700 });
  const archive = await open(archivePath, "r");
  const directoryModes = [];
  const symlinks = [];
  let position = 0;
  let totalBytes = 0;
  try {
    const magic = await readExact(archive, MAGIC.length, position);
    position += MAGIC.length;
    if (!magic.equals(MAGIC)) {
      throw new Error("dependency archive magic is invalid");
    }
    for (const expected of manifest.tree) {
      const headerLengthBytes = await readExact(archive, 4, position);
      position += 4;
      const headerLength = headerLengthBytes.readUInt32BE();
      if (headerLength === 0 || headerLength > MAX_HEADER_BYTES) {
        throw new Error("dependency archive header length is invalid");
      }
      const header = JSON.parse(
        (await readExact(archive, headerLength, position)).toString("utf8"),
      );
      position += headerLength;
      if (JSON.stringify(header) !== JSON.stringify(expected)) {
        throw new Error("dependency archive entry differs from its manifest");
      }
      const targetPath = assertSafeArtifactPath(
        nodeModulesRoot,
        path.join(nodeModulesRoot, ...expected.path.split("/")),
      );
      await mkdir(path.dirname(targetPath), { recursive: true, mode: 0o700 });
      if (expected.type === "directory") {
        await mkdir(targetPath, { recursive: false, mode: 0o700 });
        directoryModes.push([targetPath, expected.mode]);
      } else if (expected.type === "symlink") {
        const lexicalTarget = path.resolve(
          path.dirname(targetPath),
          expected.target,
        );
        if (
          lexicalTarget !== nodeModulesRoot &&
          !lexicalTarget.startsWith(`${nodeModulesRoot}${path.sep}`)
        ) {
          throw new Error("dependency archive symlink escapes node_modules");
        }
        await symlink(expected.target, targetPath);
        symlinks.push(targetPath);
      } else {
        const content = await readExact(archive, expected.size, position);
        position += expected.size;
        totalBytes += content.length;
        if (digest(content) !== expected.sha256) {
          throw new Error("dependency archive file digest mismatch");
        }
        const file = await open(targetPath, "wx", expected.mode);
        try {
          await file.write(content);
        } finally {
          await file.close();
        }
        await chmod(targetPath, expected.mode);
      }
    }
    const sentinel = await readExact(archive, 4, position);
    position += 4;
    if (sentinel.readUInt32BE() !== 0 || position !== archiveStat.size) {
      throw new Error("dependency archive has trailing or missing records");
    }
  } finally {
    await archive.close();
  }
  if (totalBytes !== manifest.totalBytes) {
    throw new Error("dependency archive extracted byte count is invalid");
  }
  const rootRealPath = await realpath(nodeModulesRoot);
  for (const linkPath of symlinks) {
    const finalTarget = await realpath(linkPath);
    if (
      finalTarget !== rootRealPath &&
      !finalTarget.startsWith(`${rootRealPath}${path.sep}`)
    ) {
      throw new Error("extracted dependency symlink escapes node_modules");
    }
  }
  for (const [directory, mode] of directoryModes.sort(
    (left, right) => right[0].length - left[0].length,
  )) {
    await chmod(directory, mode);
  }
  await chmod(nodeModulesRoot, 0o755);
  return { verified: true, fileCount: manifest.fileCount };
}

async function main() {
  const [mode, ...args] = process.argv.slice(2);
  if (mode === "validate-source") {
    if (args.length !== 1) {
      throw new Error(
        "usage: node dependency-snapshot.mjs validate-source <repository>",
      );
    }
    await validateDependencySource(path.resolve(args[0]));
    process.stdout.write('{"valid":true}\n');
    return;
  }
  const [
    repositoryRoot,
    agentRunId,
    baseSha,
    workflowRunId,
    runAttempt,
    npmVersion,
    archivePath,
    manifestPath,
  ] = args;
  if (
    !["create", "verify"].includes(mode) ||
    !repositoryRoot ||
    !agentRunId ||
    !baseSha ||
    !workflowRunId ||
    !runAttempt ||
    !npmVersion ||
    !archivePath ||
    !manifestPath ||
    args.length !== 8
  ) {
    throw new Error(
      "usage: node dependency-snapshot.mjs <create|verify> <repository> <run-id> <base-sha> <workflow-run-id> <attempt> <npm-version> <archive> <manifest>",
    );
  }
  const input = {
    repositoryRoot: path.resolve(repositoryRoot),
    agentRunId,
    baseSha,
    workflowRunId,
    runAttempt,
    npmVersion,
    archivePath: path.resolve(archivePath),
    manifestPath: path.resolve(manifestPath),
  };
  const result =
    mode === "create"
      ? await createDependencySnapshot(input)
      : await verifyDependencySnapshot(input);
  process.stdout.write(
    `${JSON.stringify(
      mode === "create"
        ? { created: true, fileCount: result.fileCount }
        : result,
    )}\n`,
  );
}
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  await main();
}
