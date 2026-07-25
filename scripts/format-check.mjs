import { readdir, readFile } from "node:fs/promises";
import { extname, join, relative } from "node:path";

const projectRoot = process.cwd();
const rootFiles = [
  ".editorconfig",
  ".gitattributes",
  ".gitignore",
  ".node-version",
  "AGENTS.md",
  "README.md",
  "package-lock.json",
  "package.json",
];
const sourceDirectories = [".github", "scripts", "src", "tests"];
const textExtensions = new Set([".json", ".md", ".mjs", ".yaml", ".yml"]);

async function collectTextFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const path = join(directory, entry.name);

    if (entry.isDirectory()) {
      files.push(...(await collectTextFiles(path)));
    } else if (textExtensions.has(extname(entry.name))) {
      files.push(path);
    }
  }

  return files;
}

const files = [
  ...rootFiles.map((file) => join(projectRoot, file)),
  ...(
    await Promise.all(
      sourceDirectories.map((directory) =>
        collectTextFiles(join(projectRoot, directory)),
      ),
    )
  ).flat(),
].sort();
const problems = [];

for (const file of files) {
  const buffer = await readFile(file);
  const text = buffer.toString("utf8");
  const displayPath = relative(projectRoot, file);

  if (!Buffer.from(text, "utf8").equals(buffer)) {
    problems.push(`${displayPath}: file is not valid UTF-8`);
  }

  if (text.startsWith("\uFEFF")) {
    problems.push(`${displayPath}: remove the UTF-8 byte-order mark`);
  }

  if (text.includes("\r")) {
    problems.push(`${displayPath}: use LF line endings`);
  }

  if (!text.endsWith("\n")) {
    problems.push(`${displayPath}: add a final newline`);
  }

  if (text.endsWith("\n\n")) {
    problems.push(`${displayPath}: remove blank lines at end of file`);
  }

  if (text.includes("\t")) {
    problems.push(`${displayPath}: replace tab indentation with spaces`);
  }

  text.split("\n").forEach((line, index) => {
    if (/[ \t]+$/.test(line)) {
      problems.push(`${displayPath}:${index + 1}: remove trailing whitespace`);
    }
  });

  if (extname(file) === ".json") {
    const formatted = `${JSON.stringify(JSON.parse(text), null, 2)}\n`;

    if (text !== formatted) {
      problems.push(`${displayPath}: format JSON with two-space indentation`);
    }
  }
}

if (problems.length > 0) {
  console.error(problems.join("\n"));
  process.exit(1);
}

console.log(`Formatting verified for ${files.length} files.`);
