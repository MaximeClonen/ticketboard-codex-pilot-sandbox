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

## Human-governed Ticketboard Codex pilot bootstrap

The Ticketboard Codex pilot execution layer may be installed or updated
only through a human-authored governance pull request.

The governance exception is limited to:

- `.github/workflows/ticketboard-codex-pilot.yml`
- `.ticketboard/codex-pilot/**`

The files must originate from the reviewed Ticketboard bootstrap
manifest and must retain their reviewed SHA-256 values and immutable
action pins.

This governance exception does not apply to model-authored pilot work.

For PILOT-1 and all Codex-generated changes, these paths remain
forbidden:

- `.github/**`
- `.ticketboard/**`
- `scripts/**`
- `AGENTS.md`
- `package.json`
- `package-lock.json`
- `.env`
- credentials, keys, tokens, and environment files

The model may modify only the exact allowed paths recorded in the
approved Ticketboard agent run.
