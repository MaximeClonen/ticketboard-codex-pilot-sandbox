import { chmod, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { assertNoSecretLike, safePlainText } from "./secret-policy.mjs";
import { validateRuntimeUsage } from "./redact-jsonl.mjs";

const REPOSITORY = "MaximeClonen/ticketboard-codex-pilot-sandbox";
const REPOSITORY_ID = "1312323027";
const MAX_SETUP_DURATION_MS = 900_000;
const PRE_CAPABILITY_FAILURE_CODES = new Set([
  "RUNNER_CONTEXT_STALE",
  "RUNNER_BASE_SHA_MISMATCH",
  "RUNNER_SETUP_FAILED",
  "PATCH_POLICY_DENIED",
  "PATCH_APPLY_FAILED",
  "VERIFICATION_FAILED",
  "GITHUB_APP_AUTH_FAILED",
  "RUN_CANCELLED",
]);

function exactKeys(value, keys) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) ===
      JSON.stringify([...keys].sort())
  );
}

function assertClosedBody(value, keys, label) {
  if (!exactKeys(value, keys)) {
    throw new Error(`${label} is not a closed wire object`);
  }
  return value;
}

function validInstant(value) {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function validFutureInstant(value, maximumFutureSeconds) {
  if (!validInstant(value)) return false;
  const offset = Date.parse(value) - Date.now();
  return offset > -5_000 && offset <= maximumFutureSeconds * 1000;
}

function safeReasonCodes(value) {
  if (
    !Array.isArray(value) ||
    value.length > 50 ||
    new Set(value).size !== value.length ||
    value.some(
      (code) =>
        typeof code !== "string" || !/^[A-Z][A-Z0-9_]{2,79}$/.test(code),
    )
  ) {
    throw new Error("validation reason codes are invalid");
  }
  return value;
}

function trustedBaseUrl() {
  const raw = process.env.TICKETBOARD_AGENT_URL;
  if (!raw) throw new Error("TICKETBOARD_AGENT_URL is required");
  const url = new URL(raw);
  if (url.protocol !== "https:" || url.username || url.password) {
    throw new Error("Ticketboard agent URL must be credential-free HTTPS");
  }
  return url.href.replace(/\/$/, "");
}

function validateRunId(runId) {
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      runId,
    )
  ) {
    throw new Error("agent run ID must be a UUID");
  }
}

function validateWorkspaceId(workspaceId) {
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      workspaceId,
    )
  ) {
    throw new Error("workspace ID must be a UUID");
  }
}

function workflowCoordinates() {
  const workflowRunId = Number(process.env.GITHUB_RUN_ID);
  const workflowRunAttempt = Number(process.env.GITHUB_RUN_ATTEMPT);
  const workflowSha = process.env.GITHUB_SHA ?? "";
  const repository = process.env.GITHUB_REPOSITORY;
  const serverUrl = new URL(process.env.GITHUB_SERVER_URL ?? "");
  if (
    !Number.isSafeInteger(workflowRunId) ||
    workflowRunId < 1 ||
    !Number.isSafeInteger(workflowRunAttempt) ||
    workflowRunAttempt < 1 ||
    workflowRunAttempt > 100 ||
    !/^[0-9a-f]{40}$/.test(workflowSha) ||
    repository !== REPOSITORY ||
    serverUrl.origin !== "https://github.com"
  ) {
    throw new Error("GitHub workflow coordinates are invalid");
  }
  return {
    workflowRunId,
    workflowRunAttempt,
    workflowSha,
    workflowUrl: `${serverUrl.origin}/${repository}/actions/runs/${workflowRunId}`,
  };
}

async function writePrivate(filePath, value) {
  await writeFile(filePath, value, { encoding: "utf8", mode: 0o600 });
  await chmod(filePath, 0o600);
}

async function readSecret(filePath) {
  const value = (await readFile(filePath, "utf8")).trim();
  if (value.length < 16 || value.length > 8192 || /[\r\n]/.test(value)) {
    throw new Error("private credential file is invalid");
  }
  return value;
}

export async function apiRequest(
  runId,
  pathname,
  { workspaceId, bearer, capability, claimToken, method = "POST", body },
) {
  validateRunId(runId);
  validateWorkspaceId(workspaceId);
  const headers = {
    Accept: "application/json",
    "Content-Type": "application/json",
    "X-Workspace-Id": workspaceId,
  };
  if (bearer) headers.Authorization = `Bearer ${bearer}`;
  if (capability) headers["X-Agent-Publish-Capability"] = capability;
  if (claimToken) headers["X-Agent-Claim-Token"] = claimToken;

  const response = await fetch(
    `${trustedBaseUrl()}/api/v1/internal/agent-pilot/runs/${runId}${pathname}`,
    {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
    },
  );
  if (!response.ok) {
    throw new Error(
      `Ticketboard request rejected with HTTP ${response.status}`,
    );
  }
  const text = await response.text();
  if (text.length > 256 * 1024) {
    throw new Error("Ticketboard response exceeded the safe size bound");
  }
  return text.length === 0 ? null : JSON.parse(text);
}

export async function requestOidc(outputPath, audience) {
  if (audience !== "ticketboard-agent-runner") {
    throw new Error("unexpected OIDC audience");
  }
  const requestToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  const requestUrl = new URL(process.env.ACTIONS_ID_TOKEN_REQUEST_URL ?? "");
  if (
    !requestToken ||
    requestUrl.protocol !== "https:" ||
    requestUrl.hostname !== "token.actions.githubusercontent.com"
  ) {
    throw new Error("trusted GitHub OIDC request coordinates are unavailable");
  }
  requestUrl.searchParams.set("audience", audience);
  const response = await fetch(requestUrl, {
    headers: { Authorization: `bearer ${requestToken}` },
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) throw new Error("GitHub OIDC token request failed");
  const payload = await response.json();
  if (typeof payload.value !== "string") {
    throw new Error("GitHub OIDC response did not contain a token");
  }
  await writePrivate(outputPath, `${payload.value}\n`);
}

export async function claim(
  oidcPath,
  workspaceId,
  runId,
  baseSha,
  setupDurationMs,
  claimPath,
  contextPath,
) {
  validateRunId(runId);
  if (!/^[0-9a-f]{40}$/.test(baseSha)) {
    throw new Error("base SHA must be a lowercase full commit SHA");
  }
  const setupDurationText = String(setupDurationMs);
  const parsedSetupDurationMs = Number(setupDurationText);
  if (
    !/^(?:0|[1-9][0-9]*)$/.test(setupDurationText) ||
    !Number.isSafeInteger(parsedSetupDurationMs) ||
    parsedSetupDurationMs < 0 ||
    parsedSetupDurationMs > MAX_SETUP_DURATION_MS
  ) {
    throw new Error("setup duration is outside the trusted runner bound");
  }
  const bearer = await readSecret(oidcPath);
  const coordinates = workflowCoordinates();
  const response = await apiRequest(runId, "/claim", {
    workspaceId,
    bearer,
    body: {
      ...coordinates,
      expectedBaseSha: baseSha,
      setupDurationMs: parsedSetupDurationMs,
    },
  });
  if (
    !exactKeys(response, [
      "attempt",
      "baseSha",
      "claimToken",
      "leaseExpiresAt",
      "runId",
      "workflowRunId",
    ]) ||
    response.runId !== runId ||
    response.workflowRunId !== coordinates.workflowRunId ||
    response?.baseSha !== baseSha ||
    !Number.isSafeInteger(response.attempt) ||
    response.attempt < 1 ||
    response.attempt > 100 ||
    !validFutureInstant(response.leaseExpiresAt, 3_600) ||
    typeof response?.claimToken !== "string" ||
    response.claimToken.length < 16 ||
    response.claimToken.length > 8192 ||
    /[\r\n]/.test(response.claimToken)
  ) {
    throw new Error("claim response failed exact workflow/run/base binding");
  }
  await writePrivate(claimPath, `${response.claimToken}\n`);

  const context = await apiRequest(runId, "/context", {
    workspaceId,
    bearer,
    claimToken: response.claimToken,
    method: "GET",
  });
  if (
    context?.agentRunId !== runId ||
    context?.repository?.baseSha !== baseSha ||
    context?.repository?.id !== REPOSITORY_ID ||
    context?.repository?.fullName !== REPOSITORY
  ) {
    throw new Error(
      "context response failed exact run/base/repository binding",
    );
  }
  await writePrivate(contextPath, `${JSON.stringify(context)}\n`);
}

export async function heartbeat(
  oidcPath,
  claimPath,
  workspaceId,
  runId,
  alivePath,
  intervalSeconds,
) {
  validateRunId(runId);
  const interval = Number(intervalSeconds);
  if (!Number.isSafeInteger(interval) || interval < 15 || interval > 120) {
    throw new Error("heartbeat interval is outside the safe bound");
  }
  while (true) {
    try {
      await readFile(alivePath);
    } catch {
      return;
    }
    await requestOidc(oidcPath, "ticketboard-agent-runner");
    const [bearer, claimToken] = await Promise.all([
      readSecret(oidcPath),
      readSecret(claimPath),
    ]);
    const response = await apiRequest(runId, "/heartbeat", {
      workspaceId,
      bearer,
      claimToken,
    });
    if (
      response?.id !== runId ||
      response?.status !== "RUNNING" ||
      !Number.isSafeInteger(response?.attempt) ||
      response.attempt < 1 ||
      !validFutureInstant(response?.leaseExpiresAt, 3_600) ||
      !validInstant(response?.lastHeartbeatAt)
    ) {
      throw new Error("heartbeat acknowledgement failed exact run binding");
    }
    await new Promise((resolve) => setTimeout(resolve, interval * 1000));
  }
}

export async function reportPatch(
  oidcPath,
  claimPath,
  workspaceId,
  manifestPath,
) {
  const [bearer, claimToken, manifest] = await Promise.all([
    readSecret(oidcPath),
    readSecret(claimPath),
    readFile(manifestPath, "utf8").then(JSON.parse),
  ]);
  validateRunId(manifest.agentRunId);
  const coordinates = workflowCoordinates();
  const response = await apiRequest(manifest.agentRunId, "/patch", {
    workspaceId,
    bearer,
    claimToken,
    body: {
      workflowRunId: coordinates.workflowRunId,
      workflowRunAttempt: coordinates.workflowRunAttempt,
      baseSha: manifest.baseSha,
      patchSha256: manifest.patchSha256,
      structuredResultSha256: manifest.resultSha256,
      changedFileCount: manifest.fileCount,
      patchBytes: manifest.byteCount,
      codexRuntime: "openai/codex-action",
      codexModel: manifest.codex.model,
      codexVersion: manifest.codex.cliVersion,
    },
  });
  if (
    !exactKeys(response, [
      "changedFileCount",
      "patchBytes",
      "patchSha256",
      "runId",
      "stage",
      "structuredResultSha256",
    ]) ||
    response.runId !== manifest.agentRunId ||
    response.stage !== "VALIDATING" ||
    response.patchSha256 !== manifest.patchSha256 ||
    response.structuredResultSha256 !== manifest.resultSha256 ||
    response.changedFileCount !== manifest.fileCount ||
    response.patchBytes !== manifest.byteCount
  ) {
    throw new Error("patch candidate acknowledgement failed exact binding");
  }
}

export function buildValidationRequest(
  manifest,
  validationRecord,
  coordinates,
) {
  assertClosedBody(
    validationRecord,
    ["outcome", "reasonCodes"],
    "validation record",
  );
  if (!["ALLOWED", "DENIED", "FAILED"].includes(validationRecord.outcome)) {
    throw new Error("trusted validation outcome is invalid");
  }
  const reasonCodes = safeReasonCodes(validationRecord.reasonCodes);
  if (
    (validationRecord.outcome === "ALLOWED" && reasonCodes.length !== 0) ||
    (validationRecord.outcome !== "ALLOWED" && reasonCodes.length === 0)
  ) {
    throw new Error("validation outcome and reason codes disagree");
  }
  const verification =
    validationRecord.outcome === "ALLOWED"
      ? [
          {
            stepCode: "VERIFY",
            outcome: "PASSED",
            durationMs: 0,
            failureCode: null,
          },
        ]
      : validationRecord.outcome === "DENIED"
        ? [
            {
              stepCode: "VERIFY",
              outcome: "SKIPPED",
              durationMs: 0,
              failureCode: null,
            },
          ]
        : [
            {
              stepCode: "VERIFY",
              outcome: "FAILED",
              durationMs: 0,
              failureCode: "VERIFICATION_FAILED",
            },
          ];
  return assertClosedBody(
    {
      workflowRunId: coordinates.workflowRunId,
      workflowRunAttempt: coordinates.workflowRunAttempt,
      providerRepositoryId: Number(REPOSITORY_ID),
      baseSha: manifest.baseSha,
      patchSha256: manifest.patchSha256,
      structuredResultSha256: manifest.resultSha256,
      outcome: validationRecord.outcome,
      verification,
      reasonCodes,
    },
    [
      "baseSha",
      "outcome",
      "patchSha256",
      "providerRepositoryId",
      "reasonCodes",
      "structuredResultSha256",
      "verification",
      "workflowRunAttempt",
      "workflowRunId",
    ],
    "validation request",
  );
}

export async function reportValidation(
  oidcPath,
  workspaceId,
  manifestPath,
  validationRecordPath,
) {
  const [bearer, manifest, validationRecord] = await Promise.all([
    readSecret(oidcPath),
    readFile(manifestPath, "utf8").then(JSON.parse),
    readFile(validationRecordPath, "utf8").then(JSON.parse),
  ]);
  validateRunId(manifest.agentRunId);
  const coordinates = workflowCoordinates();
  const body = buildValidationRequest(manifest, validationRecord, coordinates);
  const response = await apiRequest(manifest.agentRunId, "/validation", {
    workspaceId,
    bearer,
    body,
  });
  const expectedStage = {
    ALLOWED: "PATCH_READY",
    DENIED: "BLOCKED",
    FAILED: "FAILED",
  }[body.outcome];
  const expectedStep = {
    ALLOWED: {
      code: "VERIFY",
      status: "PASSED",
      summary: "Completed in 0 ms.",
    },
    DENIED: {
      code: "VERIFY",
      status: "SKIPPED",
      summary: "Completed in 0 ms.",
    },
    FAILED: {
      code: "VERIFY",
      status: "FAILED",
      summary: "VERIFICATION_FAILED",
    },
  }[body.outcome];
  const actualStep = response?.verification?.[0];
  if (
    !exactKeys(response, [
      "outcome",
      "patchSha256",
      "runId",
      "stage",
      "verification",
    ]) ||
    response.runId !== manifest.agentRunId ||
    response.outcome !== body.outcome ||
    response.stage !== expectedStage ||
    response.patchSha256 !== manifest.patchSha256 ||
    !Array.isArray(response.verification) ||
    response.verification.length !== 1 ||
    !exactKeys(actualStep, ["code", "completedAt", "status", "summary"]) ||
    actualStep.code !== expectedStep.code ||
    actualStep.status !== expectedStep.status ||
    actualStep.summary !== expectedStep.summary ||
    !validInstant(actualStep.completedAt)
  ) {
    throw new Error("validation acknowledgement failed exact binding");
  }
}

export async function reportFailure(
  oidcPath,
  workspaceId,
  runId,
  stage,
  failureCode,
) {
  const bearer = await readSecret(oidcPath);
  const coordinates = workflowCoordinates();
  const response = await apiRequest(runId, "/failure", {
    workspaceId,
    bearer,
    body: {
      workflowRunId: coordinates.workflowRunId,
      workflowRunAttempt: coordinates.workflowRunAttempt,
      stage,
      failureCode,
    },
  });
  if (
    !exactKeys(response, ["failureCode", "runId", "stage", "status"]) ||
    response.runId !== runId ||
    response.stage !== stage ||
    response.failureCode !== failureCode ||
    !["RECORDED", "IDEMPOTENT"].includes(response.status)
  ) {
    throw new Error("failure acknowledgement failed exact binding");
  }
}

export async function authorizePublish(
  oidcPath,
  workspaceId,
  manifestPath,
  capabilityPath,
  envelopePath,
) {
  const [bearer, manifest] = await Promise.all([
    readSecret(oidcPath),
    readFile(manifestPath, "utf8").then(JSON.parse),
  ]);
  validateRunId(manifest.agentRunId);
  const coordinates = workflowCoordinates();
  const response = await apiRequest(manifest.agentRunId, "/publication/claim", {
    workspaceId,
    bearer,
    body: {
      workflowRunId: coordinates.workflowRunId,
      workflowRunAttempt: coordinates.workflowRunAttempt,
      providerRepositoryId: Number(REPOSITORY_ID),
      baseSha: manifest.baseSha,
      patchSha256: manifest.patchSha256,
    },
  });
  if (
    !exactKeys(response, [
      "agentRunPath",
      "baseBranch",
      "baseSha",
      "branchName",
      "capability",
      "commitSubject",
      "expiresAt",
      "patchSha256",
      "providerRepositoryId",
      "pullRequestTitle",
      "repository",
      "runId",
      "workItemPath",
    ]) ||
    response.runId !== manifest.agentRunId ||
    typeof response.capability !== "string" ||
    response.capability.length < 16 ||
    response?.baseSha !== manifest.baseSha ||
    response?.patchSha256 !== manifest.patchSha256 ||
    String(response?.providerRepositoryId) !== REPOSITORY_ID ||
    response?.repository !== REPOSITORY
  ) {
    throw new Error("publish authorization failed exact artifact binding");
  }
  const envelope = {
    runId: response.runId,
    baseSha: response.baseSha,
    patchSha256: response.patchSha256,
    providerRepositoryId: response.providerRepositoryId,
    branchName: response.branchName,
    pullRequestTitle: response.pullRequestTitle,
    commitSubject: response.commitSubject,
    repository: response.repository,
    baseBranch: response.baseBranch,
    workItemPath: response.workItemPath,
    agentRunPath: response.agentRunPath,
  };
  await Promise.all([
    writePrivate(capabilityPath, `${response.capability}\n`),
    writePrivate(envelopePath, `${JSON.stringify(envelope, null, 2)}\n`),
  ]);
}

export async function publicationHeartbeat(
  oidcPath,
  capabilityPath,
  workspaceId,
  runId,
) {
  const [bearer, capability] = await Promise.all([
    readSecret(oidcPath),
    readSecret(capabilityPath),
  ]);
  const response = await apiRequest(runId, "/publication/heartbeat", {
    workspaceId,
    bearer,
    capability,
  });
  if (
    !exactKeys(response, ["active", "expiresAt", "runId"]) ||
    response.runId !== runId ||
    response.active !== true ||
    !validFutureInstant(response.expiresAt, 3_600)
  ) {
    throw new Error("publication capability is inactive");
  }
}

export async function reportPublicationFailure(
  oidcPath,
  capabilityPath,
  workspaceId,
  runId,
  failureCode,
) {
  const [bearer, capability] = await Promise.all([
    readSecret(oidcPath),
    readSecret(capabilityPath),
  ]);
  const coordinates = workflowCoordinates();
  const response = await apiRequest(runId, "/publication/failure", {
    workspaceId,
    bearer,
    capability,
    body: {
      workflowRunId: coordinates.workflowRunId,
      workflowRunAttempt: coordinates.workflowRunAttempt,
      stage: "PUBLICATION",
      failureCode,
    },
  });
  if (
    !exactKeys(response, ["failureCode", "runId", "stage", "status"]) ||
    response.runId !== runId ||
    response.stage !== "PUBLICATION" ||
    response.failureCode !== failureCode ||
    !["RECORDED", "IDEMPOTENT"].includes(response.status)
  ) {
    throw new Error("publication failure acknowledgement failed exact binding");
  }
}

export async function reportPublicationPreCapabilityFailure(
  oidcPath,
  workspaceId,
  runId,
  baseSha,
  patchSha256,
  failureCode,
) {
  validateRunId(runId);
  if (
    !/^[0-9a-f]{40}$/.test(baseSha) ||
    !/^[0-9a-f]{64}$/.test(patchSha256) ||
    !PRE_CAPABILITY_FAILURE_CODES.has(failureCode)
  ) {
    throw new Error("pre-capability publication failure input is invalid");
  }
  const bearer = await readSecret(oidcPath);
  const coordinates = workflowCoordinates();
  const response = await apiRequest(
    runId,
    "/publication/pre-capability-failure",
    {
      workspaceId,
      bearer,
      body: {
        workflowRunId: coordinates.workflowRunId,
        workflowRunAttempt: coordinates.workflowRunAttempt,
        providerRepositoryId: Number(REPOSITORY_ID),
        baseSha,
        patchSha256,
        failureCode,
      },
    },
  );
  if (
    !exactKeys(response, ["failureCode", "runId", "stage", "status"]) ||
    response.runId !== runId ||
    response.stage !== "PUBLICATION" ||
    response.failureCode !== failureCode ||
    !["RECORDED", "IDEMPOTENT"].includes(response.status)
  ) {
    throw new Error(
      "pre-capability publication failure acknowledgement failed exact binding",
    );
  }
}

export function buildPublicationReportBody(
  publication,
  result,
  manifest,
  coordinates,
) {
  assertClosedBody(
    publication,
    [
      "baseSha",
      "branch",
      "headSha",
      "pullRequestNumber",
      "pullRequestState",
      "pullRequestUrl",
      "repository",
    ],
    "publication result",
  );
  if (
    publication.repository !== REPOSITORY ||
    publication.baseSha !== manifest.baseSha ||
    typeof publication.branch !== "string" ||
    !/^codex\/[a-z0-9][a-z0-9-]{0,79}-[0-9a-f]{8}$/.test(publication.branch) ||
    !/^[0-9a-f]{40}$/.test(publication.headSha ?? "") ||
    !Number.isSafeInteger(publication.pullRequestNumber) ||
    publication.pullRequestNumber < 1 ||
    publication.pullRequestUrl !==
      `https://github.com/${REPOSITORY}/pull/${publication.pullRequestNumber}` ||
    publication.pullRequestState !== "DRAFT"
  ) {
    throw new Error("publication result failed exact repository binding");
  }
  assertNoSecretLike(result, "structured result");
  const runtimeUsage = validateRuntimeUsage(manifest.runtimeUsage);
  const testsPassed = 1;
  const testsFailed = 0;
  const acceptanceCriteriaPassed = result.acceptanceCriteria.filter(
    ({ status }) => status === "MET",
  ).length;
  const acceptanceCriteriaFailed =
    result.acceptanceCriteria.length - acceptanceCriteriaPassed;
  const body = {
    workflowRunId: coordinates.workflowRunId,
    workflowRunAttempt: coordinates.workflowRunAttempt,
    providerRepositoryId: Number(REPOSITORY_ID),
    baseSha: manifest.baseSha,
    patchSha256: manifest.patchSha256,
    branch: publication.branch,
    headSha: publication.headSha,
    pullRequestNumber: publication.pullRequestNumber,
    pullRequestUrl: publication.pullRequestUrl,
    summary: safePlainText(result.summary, 1000),
    testsPassed,
    testsFailed,
    acceptanceCriteriaPassed,
    acceptanceCriteriaFailed,
    verification: [
      {
        stepCode: "VERIFY",
        outcome: "PASSED",
        durationMs: 0,
        failureCode: null,
      },
    ],
    riskCodes: result.riskCodes,
    followUpCodes: result.followUpCodes,
    inputTokens: runtimeUsage.inputTokens,
    outputTokens: runtimeUsage.outputTokens,
    costMinorUnits: null,
    costCurrency: null,
  };
  return assertClosedBody(
    body,
    [
      "acceptanceCriteriaFailed",
      "acceptanceCriteriaPassed",
      "baseSha",
      "branch",
      "costCurrency",
      "costMinorUnits",
      "followUpCodes",
      "headSha",
      "inputTokens",
      "outputTokens",
      "patchSha256",
      "providerRepositoryId",
      "pullRequestNumber",
      "pullRequestUrl",
      "riskCodes",
      "summary",
      "testsFailed",
      "testsPassed",
      "verification",
      "workflowRunAttempt",
      "workflowRunId",
    ],
    "publication report",
  );
}

export function assertPublicationResponse(response, publication) {
  if (
    !exactKeys(response, [
      "branchName",
      "draft",
      "headSha",
      "pullRequestNumber",
      "pullRequestUrl",
      "state",
    ]) ||
    response.branchName !== publication.branch ||
    response.headSha !== publication.headSha ||
    response.pullRequestNumber !== publication.pullRequestNumber ||
    response.pullRequestUrl !== publication.pullRequestUrl ||
    response.state !== "DRAFT" ||
    response.draft !== true
  ) {
    throw new Error("publication response failed exact draft binding");
  }
  return response;
}

export async function reportPublication(
  oidcPath,
  capabilityPath,
  workspaceId,
  publicationPath,
  resultPath,
  manifestPath,
) {
  const [bearer, capability, publication, result, manifest] = await Promise.all(
    [
      readSecret(oidcPath),
      readSecret(capabilityPath),
      readFile(publicationPath, "utf8").then(JSON.parse),
      readFile(resultPath, "utf8").then(JSON.parse),
      readFile(manifestPath, "utf8").then(JSON.parse),
    ],
  );
  validateRunId(manifest.agentRunId);
  const coordinates = workflowCoordinates();
  const body = buildPublicationReportBody(
    publication,
    result,
    manifest,
    coordinates,
  );
  const response = await apiRequest(
    manifest.agentRunId,
    "/publication/report",
    {
      workspaceId,
      bearer,
      capability,
      body,
    },
  );
  return assertPublicationResponse(response, publication);
}
async function main() {
  const [command, ...args] = process.argv.slice(2);
  const commands = {
    "request-oidc": requestOidc,
    claim,
    heartbeat,
    "report-patch": reportPatch,
    "report-validation": reportValidation,
    "report-failure": reportFailure,
    "authorize-publish": authorizePublish,
    "publication-heartbeat": publicationHeartbeat,
    "report-publication-failure": reportPublicationFailure,
    "report-publication-pre-capability-failure":
      reportPublicationPreCapabilityFailure,
    "report-publication": reportPublication,
  };
  const handler = commands[command];
  if (!handler) throw new Error("unsupported Ticketboard client command");
  await handler(...args);
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  await main();
}
