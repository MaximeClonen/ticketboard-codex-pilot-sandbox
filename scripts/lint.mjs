import { readdir } from "node:fs/promises";
import { join, relative } from "node:path";
import { spawnSync } from "node:child_process";

const projectRoot = process.cwd();
const sourceDirectories = ["scripts", "src", "tests"];

async function collectModules(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const modules = [];

  for (const entry of entries) {
    const path = join(directory, entry.name);

    if (entry.isDirectory()) {
      modules.push(...(await collectModules(path)));
    } else if (entry.name.endsWith(".mjs")) {
      modules.push(path);
    }
  }

  return modules;
}

const modules = (
  await Promise.all(
    sourceDirectories.map((directory) =>
      collectModules(join(projectRoot, directory)),
    ),
  )
)
  .flat()
  .sort();

for (const modulePath of modules) {
  const result = spawnSync(process.execPath, ["--check", modulePath], {
    stdio: "inherit",
  });

  if (result.error) {
    throw result.error;
  }

  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

console.log(
  `Syntax verified for ${modules.length} modules: ${modules
    .map((modulePath) => relative(projectRoot, modulePath))
    .join(", ")}`,
);
