# Ticketboard Codex pilot sandbox

Deze publieke repository is een extreem kleine, volledig synthetische
Node.js-sandbox voor een toekomstige handmatige Ticketboard/Codex-pilot.

Dit is geen productiecode en dit is niet de Ticketboard-productrepository.
De inhoud is niet afkomstig uit MarketResearcherBoard of een andere
productrepository.

## Vereisten

- Node.js 24
- npm
- Git

## Lokale installatie

Maak of vernieuw eerst uitsluitend de lockfile en installeer daarna exact de
vergrendelde dependency tree:

```text
npm install --package-lock-only --ignore-scripts
npm ci
```

Het project heeft geen runtime- of developmentdependencies. `npm ci` valideert
wel dat `package.json` en `package-lock.json` synchroon zijn.

## Commando's

```text
npm run format:check
npm run lint
npm test
npm run build
npm run verify
```

- `npm run format:check` controleert de tekst- en JSON-opmaak.
- `npm run lint` voert een syntaxcontrole uit op alle `.mjs`-modules.
- `npm test` gebruikt uitsluitend de ingebouwde `node:test`-runner.
- `npm run build` maakt een nieuwe, wegwerpbare `dist/` met de module en een
  deterministische `manifest.json`.
- `npm run verify` voert alle mergegates in bovenstaande volgorde uit.

`dist/` is lokale buildoutput en wordt nooit gecommit.

## Synthetische functie

`createTaskSummary(input)` accepteert:

```js
{
  title: string,
  description?: string
}
```

De functie retourneert een getrimde title en description, plus het totale
aantal woorden. Een ontbrekende description wordt `""`. Een lege getrimde
title geeft altijd de fout `Title must not be empty.`. De uitvoer gebruikt geen
datum, randomwaarde, netwerktoegang of globale mutable state.

## Projectstructuur

```text
.
|-- .github/
|   |-- dependabot.yml
|   |-- pull_request_template.md
|   `-- workflows/ci.yml
|-- scripts/
|   |-- build.mjs
|   |-- format-check.mjs
|   |-- lint.mjs
|   `-- verify.mjs
|-- src/
|   `-- task-summary.mjs
|-- tests/
|   `-- task-summary.test.mjs
|-- AGENTS.md
|-- package-lock.json
|-- package.json
`-- README.md
```

## Veiligheidsgrenzen

- Alleen synthetische code en data.
- Geen secrets, tokens, API-keys, credentials, persoonlijke data of
  `.env`-bestanden.
- Geen externe API, netwerktoegang in applicatiecode, database of framework.
- Geen runtime dependency.
- Geen OpenAI-integratie, GitHub App, Codex-pilotworkflow of deployment.
- Geen directe push naar `main` en geen merge.
- Wijzigingen verlopen via een branch, verplichte tests en een pull request.
- Een toekomstige Codex-run mag uitsluitend repository-relative bestanden
  wijzigen.
- `.github/workflows/**` blijft verboden voor de eerste pilot.

Zie `AGENTS.md` voor de bindende repository-instructies.

## Geschikte toekomstige laagrisicopilottickets

1. “Voeg een optionele prioriteit toe aan de task summary.”
2. “Voeg een optioneel synthetisch label toe aan de task summary.”
3. “Voeg extra randgevaltests toe voor Unicode-witruimte in task summaries.”

Deze voorstellen zijn bewust nog niet geïmplementeerd.
