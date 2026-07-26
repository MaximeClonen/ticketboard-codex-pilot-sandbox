import { spawnSync } from "node:child_process";

const npmExecutable = process.env.npm_execpath;
const mergeGates = ["format:check", "lint", "test", "build"];

if (!npmExecutable) {
  throw new Error("Run verification through npm: npm run verify");
}

for (const mergeGate of mergeGates) {
  const result = spawnSync(
    process.execPath,
    [npmExecutable, "run", mergeGate],
    {
      env: process.env,
      stdio: "inherit",
    },
  );

  if (result.error) {
    throw result.error;
  }

  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}
