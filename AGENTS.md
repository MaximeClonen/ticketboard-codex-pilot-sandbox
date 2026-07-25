# Repository instructions

## Scope

This repository is a fully synthetic sandbox for a manual Ticketboard/Codex
pilot. It is not a production repository. Do not copy code, documentation,
fixtures, configuration, or data from MarketResearcherBoard or any other
product repository.

## Safety boundaries

- Use synthetic, non-sensitive code and data only.
- Never add secrets, tokens, API keys, credentials, personal data, `.env`
  files, repository secrets, or environment secrets.
- Application code must not access the network or call an external API.
- Do not add a database, framework, runtime dependency, OpenAI integration,
  GitHub App, deployment configuration, or pilot workflow.
- Treat `dist/` as disposable local output and never commit it.

## Change boundaries

- A future Codex run may modify repository-relative files only. Never read or
  write through absolute paths, parent-directory traversal, or files outside
  this repository.
- Do not modify GitHub workflows without an explicit ticket that authorizes the
  exact workflow change.
- `.github/workflows/**` is a prohibited path for the first pilot, even if a
  requested change appears related.
- Never push directly to `main` and never merge a pull request.
- Make changes on a branch and submit them through a pull request.

## Quality gates

- Add or update tests for every behavior change.
- Use only the built-in `node:test` runner and `node:assert` for tests.
- Run `npm run verify` before proposing a pull request.
- Keep code deterministic: no time, randomness, network access, or mutable
  global state.
