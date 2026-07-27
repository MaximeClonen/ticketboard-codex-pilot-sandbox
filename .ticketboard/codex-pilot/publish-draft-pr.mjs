import { spawnSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { sha256 } from "./patch-policy.mjs";
import { assertNoSecretLike, safePlainText } from "./secret-policy.mjs";

const PUBLICATION_KEYS = [
  "agentRunPath",
  "baseBranch",
  "baseSha",
  "branchName",
  "commitSubject",
  "patchSha256",
  "providerRepositoryId",
  "pullRequestTitle",
  "repository",
  "runId",
  "workItemPath",
].sort();
const STATE_KEYS = [
  "agentRunId",
  "baseSha",
  "branchName",
  "headSha",
  "patchSha256",
  "repositoryFullName",
  "version",
].sort();

function exactKeys(value, keys) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify(keys)
  );
}

function trustedUrl(value) {
  const expected = new URL(process.env.TICKETBOARD_PUBLIC_URL ?? "");
  if (
    expected.protocol !== "https:" ||
    expected.username ||
    expected.password ||
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 2048
  ) {
    throw new Error("Ticketboard public origin or deeplink is invalid");
  }
  const actual = new URL(value, expected);
  if (
    actual.protocol !== "https:" ||
    actual.origin !== expected.origin ||
    actual.username ||
    actual.password
  ) {
    throw new Error("Ticketboard deeplink is outside the trusted origin");
  }
  return actual.href;
}

function git(args, { cwd, appToken, allowFailure = false, timestamp } = {}) {
  const env = {
    PATH: process.env.PATH,
    SystemRoot: process.env.SystemRoot,
    HOME: process.env.HOME,
    LANG: "C.UTF-8",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_SYSTEM: "/dev/null",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_TERMINAL_PROMPT: "0",
    GIT_AUTHOR_NAME: "ticketboard-codex-pilot[bot]",
    GIT_AUTHOR_EMAIL: "ticketboard-codex-pilot[bot]@users.noreply.github.com",
    GIT_COMMITTER_NAME: "ticketboard-codex-pilot[bot]",
    GIT_COMMITTER_EMAIL:
      "ticketboard-codex-pilot[bot]@users.noreply.github.com",
  };
  if (timestamp) {
    env.GIT_AUTHOR_DATE = timestamp;
    env.GIT_COMMITTER_DATE = timestamp;
  }
  if (appToken) {
    env.GIT_CONFIG_COUNT = "1";
    env.GIT_CONFIG_KEY_0 = "http.https://github.com/.extraheader";
    env.GIT_CONFIG_VALUE_0 = `AUTHORIZATION: basic ${Buffer.from(
      `x-access-token:${appToken}`,
    ).toString("base64")}`;
  }
  const hardenedArgs = [
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "diff.external=",
    ...args,
  ];
  const result = spawnSync("git", hardenedArgs, {
    cwd,
    encoding: "utf8",
    env,
    maxBuffer: 1024 * 1024,
    windowsHide: true,
  });
  if (result.status !== 0 && !allowFailure) {
    throw new Error(`trusted git publication command failed: ${args[0]}`);
  }
  return result;
}

export function assertExactOrigin(repositoryPath, policy) {
  const allowed = new Set([
    `https://github.com/${policy.repository.fullName}`,
    `https://github.com/${policy.repository.fullName}.git`,
  ]);
  const fetchUrls = git(["remote", "get-url", "--all", "origin"], {
    cwd: repositoryPath,
  })
    .stdout.trim()
    .split(/\r?\n/)
    .filter(Boolean);
  const pushUrls = git(["remote", "get-url", "--push", "--all", "origin"], {
    cwd: repositoryPath,
  })
    .stdout.trim()
    .split(/\r?\n/)
    .filter(Boolean);
  if (
    fetchUrls.length !== 1 ||
    pushUrls.length !== 1 ||
    !allowed.has(fetchUrls[0]) ||
    !allowed.has(pushUrls[0])
  ) {
    throw new Error("Git origin is not the exact approved sandbox repository");
  }
}

export function validatePublicationEnvelope(envelope, manifest, policy) {
  if (!exactKeys(envelope, PUBLICATION_KEYS)) {
    throw new Error("publication envelope is not closed");
  }
  const pullRequestTitle = safePlainText(envelope.pullRequestTitle, 240);
  const commitSubject = envelope.commitSubject;
  if (
    typeof commitSubject !== "string" ||
    commitSubject.length === 0 ||
    commitSubject.length > 200 ||
    /[\u0000-\u001f\u007f]/.test(commitSubject)
  ) {
    throw new Error("publication commit subject is not bounded one-line text");
  }
  assertNoSecretLike(commitSubject, "publication commit subject");
  const exact = [
    [envelope.runId, manifest.agentRunId],
    [envelope.baseSha, manifest.baseSha],
    [envelope.patchSha256, manifest.patchSha256],
    [String(envelope.providerRepositoryId), policy.repository.id],
    [envelope.repository, policy.repository.fullName],
    [envelope.baseBranch, policy.repository.defaultBranch],
  ];
  if (
    exact.some(([actual, expected]) => actual !== expected) ||
    !/^codex\/[a-z0-9][a-z0-9-]{0,79}-[0-9a-f]{8}$/.test(envelope.branchName) ||
    envelope.branchName === policy.repository.defaultBranch ||
    !/^feat\(pilot\): [A-Z][A-Z0-9]{0,15}-[1-9][0-9]* .{1,180}$/.test(
      commitSubject,
    )
  ) {
    throw new Error("publication envelope failed exact artifact/ref binding");
  }
  return {
    pullRequestTitle,
    commitSubject,
    workItemUrl: trustedUrl(envelope.workItemPath),
    runUrl: trustedUrl(envelope.agentRunPath),
  };
}

function validatePrerequisites({ result, policy }) {
  assertNoSecretLike(result, "structured result");
  if (
    result.outcome !== "PATCH_READY" ||
    result.recommendedRunStatus !== "REVIEW_REQUIRED" ||
    result.recommendedWorkItemTransition !== "NONE" ||
    policy.publication.draftOnly !== true ||
    policy.publication.directDefaultBranchPush !== false ||
    policy.publication.merge !== false ||
    policy.publication.deploy !== false
  ) {
    throw new Error("publication prerequisites are not satisfied");
  }
}

function safePrBody({ envelope, safe, result, manifest }) {
  const summary = safePlainText(result.summary, 1000);
  const risks =
    result.riskCodes.length === 0 ? "none" : result.riskCodes.join(", ");
  const followUps =
    result.followUpCodes.length === 0
      ? "none"
      : result.followUpCodes.join(", ");
  const acceptanceMet = result.acceptanceCriteria.filter(
    ({ status }) => status === "MET",
  ).length;

  return [
    `[Ticketboard work item](${safe.workItemUrl})`,
    `[Agent run ${envelope.runId}](${safe.runUrl})`,
    `Base SHA: \`${manifest.baseSha}\``,
    `Patch SHA-256: \`${manifest.patchSha256}\``,
    "",
    "Implementation summary (plain text):",
    summary,
    "",
    `Changed files: ${manifest.fileCount}`,
    `Acceptance criteria marked met: ${acceptanceMet}/${result.acceptanceCriteria.length}`,
    `Risk codes: ${risks}`,
    `Follow-up codes: ${followUps}`,
    "",
    "Verification:",
    "- VERIFY: PASSED",
    "",
    "> AI-generated change. Human review is required. This draft is not merged",
    "> or deployed, and Ticketboard has not transitioned or closed the work item.",
    "",
    "No full prompt, token, raw command log, source body, or model-provided link is included.",
  ].join("\n");
}

async function githubApi(pathname, { token, method = "GET", body }) {
  const response = await fetch(`https://api.github.com${pathname}`, {
    method,
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "ticketboard-codex-pilot",
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    redirect: "error",
    signal: AbortSignal.timeout(15_000),
  });
  const text = await response.text();
  if (text.length > 128 * 1024) throw new Error("GitHub response too large");
  return { response, body: text.length === 0 ? null : JSON.parse(text) };
}

async function assertExactRepository({ token, policy }) {
  const [owner, repository] = policy.repository.fullName.split("/");
  const response = await githubApi(`/repos/${owner}/${repository}`, { token });
  if (
    response.response.status !== 200 ||
    String(response.body?.id) !== policy.repository.id ||
    response.body?.full_name !== policy.repository.fullName ||
    response.body?.default_branch !== policy.repository.defaultBranch
  ) {
    throw new Error("GitHub repository identity drifted before publication");
  }
}

async function loadJson(paths) {
  return Promise.all(
    paths.map(async (file) => JSON.parse(await readFile(file, "utf8"))),
  );
}

function validateState(state, manifest, envelope, policy) {
  if (!exactKeys(state, STATE_KEYS)) {
    throw new Error("publication state is not closed");
  }
  const exact = [
    [state.version, 1],
    [state.agentRunId, manifest.agentRunId],
    [state.baseSha, manifest.baseSha],
    [state.patchSha256, manifest.patchSha256],
    [state.repositoryFullName, policy.repository.fullName],
    [state.branchName, envelope.branchName],
  ];
  if (
    exact.some(([actual, expected]) => actual !== expected) ||
    !/^[0-9a-f]{40}$/.test(state.headSha)
  ) {
    throw new Error("publication state failed exact artifact binding");
  }
  return state;
}

async function prepare([
  repositoryPath,
  patchPath,
  manifestPath,
  resultPath,
  policyPath,
  envelopePath,
  statePath,
]) {
  if (
    !repositoryPath ||
    !patchPath ||
    !manifestPath ||
    !resultPath ||
    !policyPath ||
    !envelopePath ||
    !statePath
  ) {
    throw new Error(
      "usage: publish-draft-pr.mjs prepare <repo> <patch> <manifest> <result> <policy> <envelope> <state-out>",
    );
  }
  const [manifest, result, policy, envelope] = await loadJson([
    manifestPath,
    resultPath,
    policyPath,
    envelopePath,
  ]);
  const patchText = await readFile(patchPath, "utf8");
  assertExactOrigin(repositoryPath, policy);
  const safe = validatePublicationEnvelope(envelope, manifest, policy);
  validatePrerequisites({ result, policy });
  if (sha256(patchText) !== manifest.patchSha256) {
    throw new Error("patch changed after credentialless verification");
  }

  const head = git(["rev-parse", "HEAD"], {
    cwd: repositoryPath,
  }).stdout.trim();
  if (head !== manifest.baseSha) {
    throw new Error("fresh checkout is not at the exact base SHA");
  }
  git(["add", "-N", "--", ...manifest.files], { cwd: repositoryPath });
  const appliedPatch = git(
    [
      "diff",
      "--binary",
      "--no-ext-diff",
      "--no-textconv",
      manifest.baseSha,
      "--",
    ],
    { cwd: repositoryPath },
  ).stdout;
  if (sha256(appliedPatch) !== manifest.patchSha256) {
    throw new Error("applied worktree does not reproduce the verified patch");
  }

  git(["switch", "-c", envelope.branchName, manifest.baseSha], {
    cwd: repositoryPath,
  });
  git(["add", "--", ...manifest.files], { cwd: repositoryPath });
  git(["diff", "--cached", "--check"], { cwd: repositoryPath });
  const stagedPatch = git(
    [
      "diff",
      "--cached",
      "--binary",
      "--no-ext-diff",
      "--no-textconv",
      manifest.baseSha,
      "--",
    ],
    { cwd: repositoryPath },
  ).stdout;
  if (sha256(stagedPatch) !== manifest.patchSha256) {
    throw new Error("staged worktree does not reproduce the verified patch");
  }
  git(["-c", "core.hooksPath=/dev/null", "commit", "-m", safe.commitSubject], {
    cwd: repositoryPath,
    timestamp: manifest.createdAt,
  });
  const headSha = git(["rev-parse", "HEAD"], {
    cwd: repositoryPath,
  }).stdout.trim();
  const state = {
    version: 1,
    agentRunId: manifest.agentRunId,
    repositoryFullName: policy.repository.fullName,
    baseSha: manifest.baseSha,
    patchSha256: manifest.patchSha256,
    branchName: envelope.branchName,
    headSha,
  };
  await writeFile(statePath, `${JSON.stringify(state, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
}

async function push([
  repositoryPath,
  manifestPath,
  policyPath,
  envelopePath,
  statePath,
]) {
  const token = process.env.GITHUB_APP_TOKEN;
  if (
    !repositoryPath ||
    !manifestPath ||
    !policyPath ||
    !envelopePath ||
    !statePath ||
    !token ||
    token.length < 20
  ) {
    throw new Error(
      "usage: publish-draft-pr.mjs push <repo> <manifest> <policy> <envelope> <state>",
    );
  }
  const [manifest, policy, envelope, state] = await loadJson([
    manifestPath,
    policyPath,
    envelopePath,
    statePath,
  ]);
  validatePublicationEnvelope(envelope, manifest, policy);
  validateState(state, manifest, envelope, policy);
  assertExactOrigin(repositoryPath, policy);
  await assertExactRepository({ token, policy });
  const [owner, repository] = policy.repository.fullName.split("/");
  const encodedBranch = envelope.branchName
    .split("/")
    .map(encodeURIComponent)
    .join("/");
  const existing = await githubApi(
    `/repos/${owner}/${repository}/git/ref/heads/${encodedBranch}`,
    { token },
  );
  if (existing.response.status === 404) {
    git(["push", "origin", `HEAD:refs/heads/${envelope.branchName}`], {
      cwd: repositoryPath,
      appToken: token,
    });
    return;
  }
  const existingSha = existing.body?.object?.sha;
  if (
    existing.response.status !== 200 ||
    existing.body?.ref !== `refs/heads/${envelope.branchName}` ||
    existing.body?.object?.type !== "commit" ||
    !/^[0-9a-f]{40}$/.test(existingSha)
  ) {
    throw new Error("GitHub publication branch lookup failed");
  }
  if (existingSha !== state.headSha) {
    throw new Error("existing publication branch collides with prepared head");
  }
}

export function assertExactPullRequest(
  pullRequest,
  envelope,
  policy,
  state,
  manifest,
) {
  if (
    pullRequest === null ||
    typeof pullRequest !== "object" ||
    pullRequest.draft !== true ||
    pullRequest.base?.ref !== policy.repository.defaultBranch ||
    pullRequest.base?.sha !== manifest.baseSha ||
    String(pullRequest.base?.repo?.id) !== policy.repository.id ||
    pullRequest.base?.repo?.full_name !== policy.repository.fullName ||
    pullRequest.head?.ref !== envelope.branchName ||
    String(pullRequest.head?.repo?.id) !== policy.repository.id ||
    pullRequest.head?.repo?.full_name !== policy.repository.fullName ||
    pullRequest.head?.sha !== state.headSha ||
    !Number.isSafeInteger(pullRequest.number) ||
    pullRequest.number < 1 ||
    typeof pullRequest.html_url !== "string" ||
    pullRequest.html_url !==
      `https://github.com/${policy.repository.fullName}/pull/${pullRequest.number}`
  ) {
    throw new Error("pull request is not the exact server-bound draft");
  }
  return pullRequest;
}

async function createPr([
  manifestPath,
  resultPath,
  policyPath,
  envelopePath,
  statePath,
  outputPath,
]) {
  const token = process.env.GITHUB_APP_TOKEN;
  if (
    !manifestPath ||
    !resultPath ||
    !policyPath ||
    !envelopePath ||
    !statePath ||
    !outputPath ||
    !token ||
    token.length < 20
  ) {
    throw new Error(
      "usage: publish-draft-pr.mjs create-pr <manifest> <result> <policy> <envelope> <state> <output>",
    );
  }
  const [manifest, result, policy, envelope, state] = await loadJson([
    manifestPath,
    resultPath,
    policyPath,
    envelopePath,
    statePath,
  ]);
  const safe = validatePublicationEnvelope(envelope, manifest, policy);
  validatePrerequisites({ result, policy });
  validateState(state, manifest, envelope, policy);
  await assertExactRepository({ token, policy });
  const [owner, repository] = policy.repository.fullName.split("/");
  const encodedBranch = envelope.branchName
    .split("/")
    .map(encodeURIComponent)
    .join("/");
  const branch = await githubApi(
    `/repos/${owner}/${repository}/git/ref/heads/${encodedBranch}`,
    { token },
  );
  if (
    branch.response.status !== 200 ||
    branch.body?.object?.sha !== state.headSha
  ) {
    throw new Error("published branch is not the prepared exact commit");
  }

  const query = new URLSearchParams({
    state: "open",
    head: `${owner}:${envelope.branchName}`,
    base: policy.repository.defaultBranch,
  });
  const existing = await githubApi(
    `/repos/${owner}/${repository}/pulls?${query.toString()}`,
    { token },
  );
  if (existing.response.status !== 200 || !Array.isArray(existing.body)) {
    throw new Error("GitHub pull request lookup failed");
  }
  if (existing.body.length > 1) {
    throw new Error("multiple pull requests exist for the exact pilot branch");
  }

  let pullRequest = existing.body[0];
  if (pullRequest) {
    pullRequest = assertExactPullRequest(
      pullRequest,
      envelope,
      policy,
      state,
      manifest,
    );
  } else {
    const created = await githubApi(`/repos/${owner}/${repository}/pulls`, {
      token,
      method: "POST",
      body: {
        title: safe.pullRequestTitle,
        body: safePrBody({
          envelope,
          safe,
          result,
          manifest,
        }),
        head: envelope.branchName,
        base: policy.repository.defaultBranch,
        draft: true,
        maintainer_can_modify: false,
      },
    });
    if (created.response.status !== 201) {
      throw new Error("GitHub did not create the required draft pull request");
    }
    pullRequest = assertExactPullRequest(
      created.body,
      envelope,
      policy,
      state,
      manifest,
    );
  }

  await writeFile(
    outputPath,
    `${JSON.stringify(
      {
        repository: policy.repository.fullName,
        baseSha: manifest.baseSha,
        branch: envelope.branchName,
        headSha: state.headSha,
        pullRequestNumber: pullRequest.number,
        pullRequestUrl: pullRequest.html_url,
        pullRequestState: "DRAFT",
      },
      null,
      2,
    )}\n`,
    { encoding: "utf8", mode: 0o600 },
  );
}

export async function cleanupOrphan([
  manifestPath,
  policyPath,
  envelopePath,
  statePath,
]) {
  const token = process.env.GITHUB_APP_TOKEN;
  if (
    !manifestPath ||
    !policyPath ||
    !envelopePath ||
    !statePath ||
    !token ||
    token.length < 20
  ) {
    throw new Error(
      "usage: publish-draft-pr.mjs cleanup-orphan <manifest> <policy> <envelope> <state>",
    );
  }
  const [manifest, policy, envelope, state] = await loadJson([
    manifestPath,
    policyPath,
    envelopePath,
    statePath,
  ]);
  validatePublicationEnvelope(envelope, manifest, policy);
  validateState(state, manifest, envelope, policy);
  await assertExactRepository({ token, policy });
  const [owner, repository] = policy.repository.fullName.split("/");
  const encodedBranch = envelope.branchName
    .split("/")
    .map(encodeURIComponent)
    .join("/");
  const branchPath = `/repos/${owner}/${repository}/git/ref/heads/${encodedBranch}`;
  const branch = await githubApi(branchPath, { token });
  if (branch.response.status === 404) return;
  if (
    branch.response.status !== 200 ||
    branch.body?.ref !== `refs/heads/${envelope.branchName}` ||
    branch.body?.object?.type !== "commit" ||
    branch.body?.object?.sha !== state.headSha
  ) {
    throw new Error("orphan cleanup refused an unknown or changed ref");
  }

  const query = new URLSearchParams({
    state: "all",
    head: `${owner}:${envelope.branchName}`,
    base: policy.repository.defaultBranch,
  });
  const pullRequests = await githubApi(
    `/repos/${owner}/${repository}/pulls?${query.toString()}`,
    { token },
  );
  if (
    pullRequests.response.status !== 200 ||
    !Array.isArray(pullRequests.body) ||
    pullRequests.body.length !== 0
  ) {
    throw new Error("orphan cleanup refused a ref with pull-request evidence");
  }

  const removed = await githubApi(
    `/repos/${owner}/${repository}/git/refs/heads/${encodedBranch}`,
    { token, method: "DELETE" },
  );
  if (removed.response.status !== 204) {
    throw new Error("GitHub did not delete the exact orphan ref");
  }
  const confirmed = await githubApi(branchPath, { token });
  if (confirmed.response.status !== 404) {
    throw new Error("orphan ref deletion could not be confirmed");
  }
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  if (command === "prepare") return prepare(args);
  if (command === "push") return push(args);
  if (command === "create-pr") return createPr(args);
  if (command === "cleanup-orphan") return cleanupOrphan(args);
  throw new Error(
    "publisher command must be prepare, push, create-pr, or cleanup-orphan",
  );
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  await main();
}
