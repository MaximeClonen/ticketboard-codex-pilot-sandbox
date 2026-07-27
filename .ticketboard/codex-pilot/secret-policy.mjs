const SECRET_PATTERNS = [
  {
    code: "PRIVATE_KEY",
    pattern: /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/i,
  },
  {
    code: "OPENAI_KEY",
    pattern: /\bsk-(?:(?:proj|svcacct)-)?[A-Za-z0-9_-]{20,}\b/,
  },
  {
    code: "GITHUB_TOKEN",
    pattern:
      /\b(?:(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/i,
  },
  {
    code: "GITLAB_TOKEN",
    pattern: /\bglpat-[A-Za-z0-9_-]{20,}\b/i,
  },
  {
    code: "NPM_TOKEN",
    pattern: /\bnpm_[A-Za-z0-9]{20,}\b/i,
  },
  {
    code: "SLACK_TOKEN",
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/i,
  },
  {
    code: "AWS_ACCESS_KEY",
    pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/,
  },
  {
    code: "GOOGLE_API_KEY",
    pattern: /\bAIza[0-9A-Za-z_-]{30,}\b/,
  },
  {
    code: "JWT",
    pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/,
  },
  {
    code: "ASSIGNED_SECRET",
    pattern:
      /\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|private[_-]?key|refresh[_-]?token|token)\s*[:=]\s*["']?[A-Za-z0-9+/_=-]{16,}/i,
  },
];

export function secretFindings(value) {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  return SECRET_PATTERNS.filter(({ pattern }) => pattern.test(text)).map(
    ({ code }) => code,
  );
}

export function assertNoSecretLike(value, label = "value") {
  const findings = secretFindings(value);
  if (findings.length > 0) {
    throw new Error(
      `${label} contains secret-like content: ${findings.join(",")}`,
    );
  }
}

export function safePlainText(value, maxLength) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maxLength ||
    /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value)
  ) {
    throw new Error("unsafe bounded publication text");
  }
  assertNoSecretLike(value, "publication text");

  return value
    .replaceAll("@", "\uFF20")
    .replace(/https?:\/\//gi, (scheme) => `${scheme.slice(0, -2)}\u200b//`)
    .replace(/([\\`*_{}\[\]<>#+!|])/g, "\\$1");
}
