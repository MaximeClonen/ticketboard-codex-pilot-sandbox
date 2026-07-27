import { createHash } from "node:crypto";
import {
  lstat,
  readFile,
  readdir,
  realpath,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const MANIFEST_KEYS = [
  "entries",
  "gitDirectory",
  "repositoryPath",
  "treeSha256",
  "version",
].sort();
const ENTRY_KEYS = ["byteCount", "mode", "path", "sha256", "type"].sort();

function exactKeys(value, keys) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify(keys)
  );
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

async function snapshotGitDirectory(repositoryPath) {
  const repository = await realpath(repositoryPath);
  const gitDirectory = path.join(repository, ".git");
  const gitStat = await lstat(gitDirectory);
  if (!gitStat.isDirectory() || gitStat.isSymbolicLink()) {
    throw new Error("repository .git boundary is not a regular directory");
  }

  const entries = [];
  async function walk(directory, relative = "") {
    const children = await readdir(directory, { withFileTypes: true });
    children.sort((left, right) => left.name.localeCompare(right.name, "en"));
    for (const child of children) {
      const absolutePath = path.join(directory, child.name);
      const relativePath = relative ? `${relative}/${child.name}` : child.name;
      const stat = await lstat(absolutePath);
      const mode = stat.mode & 0o777;
      if (stat.isSymbolicLink()) {
        throw new Error(`repository .git contains a symlink: ${relativePath}`);
      }
      if (stat.isDirectory()) {
        entries.push({
          path: relativePath,
          type: "directory",
          mode,
          byteCount: 0,
          sha256: null,
        });
        await walk(absolutePath, relativePath);
      } else if (stat.isFile()) {
        const content = await readFile(absolutePath);
        entries.push({
          path: relativePath,
          type: "file",
          mode,
          byteCount: content.length,
          sha256: sha256(content),
        });
      } else {
        throw new Error(
          `repository .git contains a non-regular entry: ${relativePath}`,
        );
      }
    }
  }
  await walk(gitDirectory);
  return {
    version: 1,
    repositoryPath: repository.replaceAll("\\", "/"),
    gitDirectory: gitDirectory.replaceAll("\\", "/"),
    entries,
    treeSha256: sha256(JSON.stringify(entries)),
  };
}

export async function captureGitBoundary(repositoryPath) {
  return snapshotGitDirectory(repositoryPath);
}

export async function assertGitBoundary(repositoryPath, expected) {
  if (
    !exactKeys(expected, MANIFEST_KEYS) ||
    expected.version !== 1 ||
    !Array.isArray(expected.entries) ||
    expected.entries.some(
      (entry) =>
        !exactKeys(entry, ENTRY_KEYS) ||
        typeof entry.path !== "string" ||
        !["directory", "file"].includes(entry.type) ||
        !Number.isSafeInteger(entry.mode) ||
        !Number.isSafeInteger(entry.byteCount) ||
        (entry.type === "file" && !/^[0-9a-f]{64}$/.test(entry.sha256 ?? "")) ||
        (entry.type === "directory" &&
          (entry.sha256 !== null || entry.byteCount !== 0)),
    ) ||
    !/^[0-9a-f]{64}$/.test(expected.treeSha256 ?? "")
  ) {
    throw new Error("trusted .git boundary manifest is invalid");
  }
  const actual = await snapshotGitDirectory(repositoryPath);
  if (
    actual.repositoryPath !== expected.repositoryPath ||
    actual.gitDirectory !== expected.gitDirectory ||
    actual.treeSha256 !== expected.treeSha256 ||
    JSON.stringify(actual.entries) !== JSON.stringify(expected.entries)
  ) {
    throw new Error("repository .git boundary changed during model execution");
  }
  return { verified: true, treeSha256: actual.treeSha256 };
}

async function main() {
  const [command, repositoryPath, manifestPath] = process.argv.slice(2);
  if (
    !["capture", "assert"].includes(command) ||
    !repositoryPath ||
    !manifestPath
  ) {
    throw new Error(
      "usage: node git-boundary.mjs <capture|assert> <repository> <manifest>",
    );
  }
  if (command === "capture") {
    const manifest = await captureGitBoundary(repositoryPath);
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600,
    });
    return;
  }
  const expected = JSON.parse(await readFile(manifestPath, "utf8"));
  const result = await assertGitBoundary(repositoryPath, expected);
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  await main();
}
