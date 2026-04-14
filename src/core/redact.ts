/**
 * Secret redaction layer.
 *
 * Defence-in-depth: called during normalization (early) AND at final output.
 * Zero external dependencies — regex + Shannon entropy only.
 */

const REDACTED = "[REDACTED]";

// ── Pattern-based redaction ──

interface RedactionRule {
  /** Regex to match the secret. Must use the global flag. */
  re: RegExp;
  /** Replacer: receives the full match and returns the redacted string. */
  replace: (m: string) => string;
}

/** Keep the label/prefix before the secret value for context. */
const prefixReplace = (m: string): string => {
  const sep = m.match(/^[^=:\s]+/);
  return sep ? `${sep[0]} ${REDACTED}` : REDACTED;
};

const RULES: RedactionRule[] = [
  // ── Original patterns (preserved) ──
  // sshpass -p 'secret' / sshpass -p "secret" / sshpass -p secret
  { re: /sshpass\s+-p\s*(?:'[^']*'|"[^"]*"|\S+)/gi, replace: () => `sshpass -p ${REDACTED}` },
  // -i path.pem
  { re: /-i\s+\S+\.pem\b/gi, replace: () => `-i ${REDACTED}` },

  // ── PEM private key blocks ──
  { re: /-----BEGIN[\w\s]*PRIVATE KEY-----[\s\S]*?-----END[\w\s]*PRIVATE KEY-----/g, replace: () => REDACTED },

  // ── Authorization headers ──
  // Authorization: Bearer eyJ...  /  Authorization: Basic dXN...
  { re: /Authorization:\s*(?:Bearer|Basic|Token)\s+\S+/gi, replace: (m) => {
    const scheme = m.match(/Authorization:\s*(\S+)/i)?.[1] ?? "";
    return `Authorization: ${scheme} ${REDACTED}`;
  }},
  // Basic base64 credentials (standalone)
  { re: /Basic\s+[A-Za-z0-9+/=]{16,}/g, replace: () => `Basic ${REDACTED}` },

  // ── curl -u user:pass ──
  { re: /curl\s[^|;]*-u\s+\S+:\S+/g, replace: (m) => m.replace(/-u\s+\S+:\S+/, `-u ${REDACTED}`) },

  // ── DSN / connection-string credentials ──
  // postgres://user:pass@host, mysql://user:pass@host, redis://:pass@host, etc.
  // Matches any URI scheme://[anything without whitespace or @]@
  { re: /([a-z][a-z0-9+.-]*):\/\/([^@\s]{1,256})@/gi,
    replace: (_m, scheme) => `${scheme}://[REDACTED]@` },

  // ── AWS keys ──
  { re: /(?:AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|aws_secret_access_key|aws_session_token)[=:\s]+\S+/gi, replace: prefixReplace },
  { re: /(?:AKIA|ASIA)[A-Z0-9]{16,}/g, replace: () => REDACTED },

  // ── GitHub tokens ──
  { re: /\b(?:ghp_|gho_|ghs_|ghr_|github_pat_)[A-Za-z0-9_]{20,}/g, replace: () => REDACTED },

  // ── OpenAI / Anthropic keys ──
  { re: /\b(?:sk-proj-|sk-ant-|sk-live-|sk-)[A-Za-z0-9_-]{20,}/g, replace: () => REDACTED },

  // ── Slack tokens ──
  { re: /\b(?:xoxb-|xoxp-|xoxo-|xoxa-|xoxr-)[A-Za-z0-9-]{20,}/g, replace: () => REDACTED },

  // ── JSON-embedded secrets ──
  // "apiKey": "sk-...", "secret": "value", "password": "value", "token": "value"
  { re: /(?:"(?:api[_-]?key|secret|password|token|auth|credential|access[_-]?key|private[_-]?key)")\s*:\s*"([^"]{8,})"/gi,
    replace: (m) => {
      const key = m.match(/"([^"]+)"\s*:/)?.[1] ?? "";
      return `"${key}": "${REDACTED}"`;
    },
  },

  // ── Generic key=value / key: value patterns ──
  // password = mysecret, api_key=abc123, secret: xyz
  { re: /(?:password|passwd|api[_-]?key|secret|token|auth[_-]?token|access[_-]?key|private[_-]?key)\s*[=:]\s*\S+/gi, replace: prefixReplace },
];

/** Apply all pattern rules to the input text. */
const patternRedact = (text: string): string => {
  let out = text;
  for (const rule of RULES) {
    // Reset lastIndex for global regexes
    rule.re.lastIndex = 0;
    out = out.replace(rule.re, rule.replace);
  }
  return out;
};

// ── Entropy-based redaction ──

/** Shannon entropy of a string (bits per character). */
const shannon = (s: string): number => {
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  const len = s.length;
  let ent = 0;
  for (const count of freq.values()) {
    const p = count / len;
    ent -= p * Math.log2(p);
  }
  return ent;
};

// Note: `=` intentionally excluded — it bridges key=value pairs (e.g. DATABASE_URL=postgres)
// and causes false positives. Base64 padding `=` is only 0-2 trailing chars and doesn't
// affect entropy detection meaningfully.
const HIGH_ENTROPY_RE = /[A-Za-z0-9+/_-]{20,}/g;
const ENTROPY_THRESHOLD = 4.0;

/** Words that look like high-entropy but are actually common code/prose tokens. */
const SAFE_TOKENS = new Set([
  "sourceIndex", "toolResult", "previousSummary", "firstKeptEntryId",
  "buildSections", "formatSummary", "normalizeOne", "truncateTokens",
  "NormalizedBlock", "TranscriptEntry", "CompileInput",
]);

/** Return true if the token is clearly NOT a secret (path, word-like, etc.). */
const isSafeToken = (token: string): boolean => {
  if (SAFE_TOKENS.has(token)) return true;
  // File paths: contain / or \
  if (/[/\\]/.test(token)) return true;
  // Pure base64 padding only
  if (/^=+$/.test(token)) return true;
  // camelCase / PascalCase identifiers (at least 2 case transitions and no digits dominating)
  if (/^[a-zA-Z]+$/.test(token) && /[a-z][A-Z]|[A-Z][a-z]/.test(token)) return true;
  // All lowercase or all uppercase short-ish tokens (likely words / constants)
  if (token.length < 30 && (/^[a-z_]+$/i.test(token) || /^[A-Z_]+$/.test(token))) return true;
  return false;
};

/** Second-pass: redact high-entropy tokens that survived pattern matching. */
const entropyRedact = (text: string): string =>
  text.replace(HIGH_ENTROPY_RE, (tok) => {
    if (isSafeToken(tok)) return tok;
    if (shannon(tok) > ENTROPY_THRESHOLD) return REDACTED;
    return tok;
  });

// ── Public API ──

export const redact = (text: string): string => entropyRedact(patternRedact(text));
