import { copyFile, mkdir, readFile, rm, writeFile } from "node:fs/promises";

const projectRoot = new URL("../", import.meta.url);
const distDirectory = new URL("dist/", projectRoot);
const packageJson = JSON.parse(
  await readFile(new URL("package.json", projectRoot), "utf8"),
);

await rm(distDirectory, { force: true, recursive: true });
await mkdir(distDirectory, { recursive: true });
await copyFile(
  new URL("src/task-summary.mjs", projectRoot),
  new URL("task-summary.mjs", distDirectory),
);
await writeFile(
  new URL("manifest.json", distDirectory),
  `${JSON.stringify(
    {
      projectName: packageJson.name,
      buildType: "synthetic",
    },
    null,
    2,
  )}\n`,
  "utf8",
);

console.log("Built disposable output in dist/.");
