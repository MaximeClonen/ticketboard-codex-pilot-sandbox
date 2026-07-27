import { createHash } from "node:crypto";
import { lstat, readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const WORKFLOW_PATH = ".github/workflows/ticketboard-codex-pilot.yml";
const HELPER_DIRECTORY = ".ticketboard/codex-pilot";
const HELPER_PREFIX = `${HELPER_DIRECTORY}/`;

function safeRelativePath(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value === value.replaceAll("\\", "/") &&
    !path.posix.isAbsolute(value) &&
    !value.split("/").includes("..") &&
    !value.split("/").includes(".")
  );
}

export async function verifyBootstrap(root, manifest) {
  if (
    manifest?.version !== 1 ||
    manifest?.bundleType !== "NON_EXECUTABLE_REVIEW_TEMPLATE" ||
    manifest?.installationMode !== "HUMAN_GOVERNANCE_PR_ONLY" ||
    !Array.isArray(manifest.files) ||
    manifest.files.length === 0
  ) {
    throw new Error("bootstrap manifest header is invalid");
  }

  const rootPath = path.resolve(root);
  const seen = new Set();
  for (const entry of manifest.files) {
    if (
      !safeRelativePath(entry?.path) ||
      (entry.path !== WORKFLOW_PATH && !entry.path.startsWith(HELPER_PREFIX)) ||
      !/^[0-9a-f]{64}$/.test(entry?.sha256 ?? "") ||
      seen.has(entry.path)
    ) {
      throw new Error("bootstrap manifest entry is invalid");
    }
    seen.add(entry.path);
    const filePath = path.resolve(rootPath, ...entry.path.split("/"));
    if (
      filePath !== rootPath &&
      !filePath.startsWith(`${rootPath}${path.sep}`)
    ) {
      throw new Error("bootstrap manifest path escaped the repository");
    }
    const stat = await lstat(filePath);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw new Error(`bootstrap entry is not a regular file: ${entry.path}`);
    }
    const digest = createHash("sha256")
      .update(await readFile(filePath))
      .digest("hex");
    if (digest !== entry.sha256) {
      throw new Error(`bootstrap digest mismatch: ${entry.path}`);
    }
  }

  const actual = new Set([WORKFLOW_PATH]);
  const workflowStat = await lstat(
    path.join(rootPath, ...WORKFLOW_PATH.split("/")),
  );
  if (!workflowStat.isFile() || workflowStat.isSymbolicLink()) {
    throw new Error(`bootstrap entry is not a regular file: ${WORKFLOW_PATH}`);
  }

  async function enumerate(directory, relative = HELPER_DIRECTORY) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const relativePath = relative ? `${relative}/${entry.name}` : entry.name;
      const absolutePath = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        throw new Error(`bootstrap contains a symlink: ${relativePath}`);
      }
      if (entry.isDirectory()) {
        await enumerate(absolutePath, relativePath);
      } else if (entry.isFile()) {
        actual.add(relativePath.replaceAll("\\", "/"));
      } else {
        throw new Error(
          `bootstrap contains a non-regular entry: ${relativePath}`,
        );
      }
    }
  }
  await enumerate(path.join(rootPath, ...HELPER_DIRECTORY.split("/")));
  if (JSON.stringify([...actual].sort()) !== JSON.stringify([...seen].sort())) {
    throw new Error(
      "bootstrap files do not exactly match the reviewed manifest",
    );
  }
  return { verified: true, fileCount: seen.size };
}

async function main() {
  const [root, manifestPath] = process.argv.slice(2);
  if (!root || !manifestPath) {
    throw new Error(
      "usage: node verify-bootstrap.mjs <repository-root> <manifest>",
    );
  }
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  const result = await verifyBootstrap(root, manifest);
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  await main();
}
