## Summary

- Describe the synthetic sandbox change.
- Explain why it is needed for the pilot.

## Safety

- [ ] Uses synthetic, non-sensitive data only.
- [ ] Adds no secrets, `.env` files, network access, database, or runtime dependency.
- [ ] Does not modify `.github/workflows/**` unless an explicit ticket allows it.
- [ ] Does not implement a Codex workflow, OpenAI integration, GitHub App, or deployment.

## Verification

- [ ] `npm run verify`
- [ ] `git diff --check`

## Scope

- [ ] Changes are limited to repository-relative files.
- [ ] This pull request will not be merged as part of the pilot bootstrap.
