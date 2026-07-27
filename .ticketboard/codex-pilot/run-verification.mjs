import { spawnSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

export function runVerificationStep({ code, command, cwd, timeoutMs }) {
  if (
    !Array.isArray(command) ||
    command.length === 0 ||
    command.some(
      (part) =>
        typeof part !== "string" ||
        part.length === 0 ||
        part.length > 200 ||
        /[\r\n\u0000]/.test(part),
    )
  ) {
    throw new Error(`trusted command mapping for ${code} is invalid`);
  }

  const startedAt = Date.now();
  const result = spawnSync(command[0], command.slice(1), {
    cwd,
    encoding: "utf8",
    env: {
      PATH: process.env.PATH,
      SystemRoot: process.env.SystemRoot,
      HOME: process.env.HOME,
      LANG: "C.UTF-8",
      CI: "true",
      NO_PROXY: "*",
      no_proxy: "*",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_TERMINAL_PROMPT: "0",
    },
    maxBuffer: 256 * 1024,
    timeout: timeoutMs,
    windowsHide: true,
  });
  const durationMs = Date.now() - startedAt;
  const timedOut = result.error?.code === "ETIMEDOUT";
  const passed = result.status === 0 && !timedOut;
  return {
    code,
    status: passed ? "PASSED" : "FAILED",
    failureCode: passed
      ? null
      : timedOut
        ? "VERIFICATION_TIMEOUT"
        : "VERIFICATION_FAILED",
    durationMs,
    summary: passed
      ? `${code} completed successfully.`
      : `${code} did not complete successfully.`,
  };
}

async function main() {
  const [repositoryPath, policyPath, outputPath] = process.argv.slice(2);
  if (!repositoryPath || !policyPath || !outputPath) {
    throw new Error(
      "usage: node run-verification.mjs <repo> <policy> <summary-out>",
    );
  }
  const policy = JSON.parse(await readFile(policyPath, "utf8"));
  const startedAt = Date.now();
  const steps = [];

  for (const code of policy.verification.stepCodes) {
    if (
      Date.now() - startedAt >
      policy.verification.totalTimeoutSeconds * 1000
    ) {
      steps.push({
        code,
        status: "FAILED",
        failureCode: "VERIFICATION_TOTAL_TIMEOUT",
        durationMs: 0,
        summary: "The total verification time bound was reached.",
      });
      break;
    }
    const command = policy.verification.commands[code];
    const step = runVerificationStep({
      code,
      command,
      cwd: repositoryPath,
      timeoutMs: policy.verification.stepTimeoutSeconds * 1000,
    });
    steps.push(step);
    if (step.status !== "PASSED") break;
  }

  const summary = {
    status:
      steps.length === policy.verification.stepCodes.length &&
      steps.every(({ status }) => status === "PASSED")
        ? "PASSED"
        : "FAILED",
    steps,
  };
  await writeFile(outputPath, `${JSON.stringify(summary, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  if (summary.status !== "PASSED") process.exitCode = 1;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  await main();
}
