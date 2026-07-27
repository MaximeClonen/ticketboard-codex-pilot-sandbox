import { createReadStream, createWriteStream } from "node:fs";
import { lstat, open, writeFile } from "node:fs/promises";
import path from "node:path";
import readline from "node:readline";
import { pathToFileURL } from "node:url";

const ALLOWED_EVENT_TYPES = new Set([
  "thread.started",
  "turn.started",
  "turn.completed",
  "turn.failed",
  "item.started",
  "item.completed",
  "error",
]);
const ALLOWED_ITEM_TYPES = new Set([
  "agent_message",
  "command_execution",
  "file_change",
  "mcp_tool_call",
  "reasoning",
  "todo_list",
  "web_search",
]);

export const MAX_PRIVATE_JSONL_BYTES = 8 * 1024 * 1024;
export const MAX_JSONL_LINE_BYTES = 128 * 1024;

const RUNTIME_USAGE_KEYS = [
  "cachedInputTokens",
  "inputTokens",
  "outputTokens",
  "source",
].sort();

function exactKeys(value, keys) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify(keys)
  );
}

function runtimeCount(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 1_000_000
    ? value
    : null;
}

export function runtimeUsageFromEvent(event) {
  if (event?.type !== "turn.completed" || event?.usage === null) return null;
  const usage = {
    source: "CODEX_RUNTIME_JSONL",
    inputTokens: runtimeCount(event?.usage?.input_tokens),
    cachedInputTokens: runtimeCount(event?.usage?.cached_input_tokens),
    outputTokens: runtimeCount(event?.usage?.output_tokens),
  };
  return Object.values(usage).some((value) => value === null) ? null : usage;
}

export function validateRuntimeUsage(value) {
  if (
    !exactKeys(value, RUNTIME_USAGE_KEYS) ||
    value.source !== "CODEX_RUNTIME_JSONL" ||
    !Number.isSafeInteger(value.inputTokens) ||
    value.inputTokens < 0 ||
    value.inputTokens > 1_000_000 ||
    !Number.isSafeInteger(value.cachedInputTokens) ||
    value.cachedInputTokens < 0 ||
    value.cachedInputTokens > value.inputTokens ||
    !Number.isSafeInteger(value.outputTokens) ||
    value.outputTokens < 0 ||
    value.outputTokens > 1_000_000
  ) {
    throw new Error("runtime usage is not a closed bounded Codex record");
  }
  return value;
}

export function redactEvent(event, sequence) {
  const type = ALLOWED_EVENT_TYPES.has(event?.type) ? event.type : "unknown";
  const safe = { sequence, type };

  if (
    (type === "item.started" || type === "item.completed") &&
    ALLOWED_ITEM_TYPES.has(event?.item?.type)
  ) {
    safe.itemType = event.item.type;
  }
  if (type === "turn.completed" && event?.usage) {
    const usage = runtimeUsageFromEvent(event);
    if (usage) safe.usage = usage;
  }
  if (type === "turn.failed" || type === "error") {
    safe.failureCode = "CODEX_EXECUTION_FAILED";
  }
  return safe;
}

async function main() {
  const [inputPath, outputPath, usageOutputPath] = process.argv.slice(2);
  if (!inputPath || !outputPath || !usageOutputPath) {
    throw new Error(
      "usage: node redact-jsonl.mjs <private-jsonl> <safe-jsonl> <runtime-usage>",
    );
  }

  const inputStat = await lstat(inputPath);
  if (
    !inputStat.isFile() ||
    inputStat.isSymbolicLink() ||
    inputStat.size > MAX_PRIVATE_JSONL_BYTES
  ) {
    throw new Error("private Codex JSONL exceeds the regular-file byte bound");
  }

  const outputHandle = await open(outputPath, "w", 0o600);
  await outputHandle.close();
  const output = createWriteStream(outputPath, { flags: "a", mode: 0o600 });
  const lines = readline.createInterface({
    input: createReadStream(inputPath, { encoding: "utf8" }),
    crlfDelay: Infinity,
  });

  let sequence = 0;
  let observedBytes = 0;
  let completedUsageCount = 0;
  let runtimeUsage = null;
  for await (const line of lines) {
    const lineBytes = Buffer.byteLength(line, "utf8");
    observedBytes += lineBytes + 1;
    if (
      lineBytes > MAX_JSONL_LINE_BYTES ||
      observedBytes > MAX_PRIVATE_JSONL_BYTES
    ) {
      throw new Error(
        "private Codex JSONL line or stream exceeds its byte bound",
      );
    }
    if (sequence >= 200 || line.trim().length === 0) continue;
    let event;
    try {
      event = JSON.parse(line);
    } catch {
      event = { type: "unknown" };
    }
    sequence += 1;
    const eventUsage = runtimeUsageFromEvent(event);
    if (eventUsage) {
      completedUsageCount += 1;
      runtimeUsage = eventUsage;
    }
    output.write(`${JSON.stringify(redactEvent(event, sequence))}\n`);
  }
  await new Promise((resolve, reject) => {
    output.on("error", reject);
    output.end(resolve);
  });
  if (completedUsageCount !== 1 || runtimeUsage === null) {
    throw new Error(
      "Codex JSONL must contain exactly one bounded runtime usage record",
    );
  }
  validateRuntimeUsage(runtimeUsage);
  await writeFile(
    usageOutputPath,
    `${JSON.stringify(runtimeUsage, null, 2)}\n`,
    { encoding: "utf8", mode: 0o600 },
  );
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  await main();
}
