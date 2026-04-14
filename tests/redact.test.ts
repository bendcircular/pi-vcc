import { describe, it, expect } from "bun:test";
import { redact } from "../src/core/redact";

// ── helpers ──
const isRedacted = (out: string) => out.includes("[REDACTED]");
const notRedacted = (out: string) => !out.includes("[REDACTED]");

describe("redact", () => {
  // ── Original patterns ──────────────────────────────────────────────

  describe("sshpass", () => {
    it("redacts sshpass -p 'secret'", () => {
      expect(isRedacted(redact("sshpass -p 'mypassword' user@host"))).toBe(true);
    });
    it("redacts sshpass -p \"secret\"", () => {
      expect(isRedacted(redact('sshpass -p "mypassword" user@host'))).toBe(true);
    });
    it("redacts sshpass -p bareword", () => {
      expect(isRedacted(redact("sshpass -p hunter2 ssh user@host"))).toBe(true);
    });
    it("preserves the sshpass command prefix", () => {
      expect(redact("sshpass -p hunter2 ssh user@host")).toContain("sshpass -p");
    });
  });

  describe("-i file.pem", () => {
    it("redacts -i path.pem in ssh command", () => {
      expect(isRedacted(redact("ssh -i ~/.ssh/id_rsa.pem ec2-user@host"))).toBe(true);
    });
    it("does not redact non-pem -i flags", () => {
      expect(notRedacted(redact("grep -i pattern file.txt"))).toBe(true);
    });
  });

  // ── PEM private key blocks ─────────────────────────────────────────

  describe("PEM private keys", () => {
    const pemBlock = [
      "-----BEGIN RSA PRIVATE KEY-----",
      "MIIEowIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4e...",
      "-----END RSA PRIVATE KEY-----",
    ].join("\n");

    it("redacts RSA PRIVATE KEY block", () => {
      expect(isRedacted(redact(pemBlock))).toBe(true);
    });
    it("redacts EC PRIVATE KEY block", () => {
      const ec = "-----BEGIN EC PRIVATE KEY-----\nABCDEF\n-----END EC PRIVATE KEY-----";
      expect(isRedacted(redact(ec))).toBe(true);
    });
    it("redacts plain PRIVATE KEY block", () => {
      const plain = "-----BEGIN PRIVATE KEY-----\nABCDEF\n-----END PRIVATE KEY-----";
      expect(isRedacted(redact(plain))).toBe(true);
    });
    it("does not redact PUBLIC KEY block", () => {
      const pub = "-----BEGIN PUBLIC KEY-----\nABCDEF\n-----END PUBLIC KEY-----";
      expect(notRedacted(redact(pub))).toBe(true);
    });
  });

  // ── Authorization headers ─────────────────────────────────────────

  describe("Authorization headers", () => {
    it("redacts Bearer token", () => {
      const out = redact("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig");
      expect(isRedacted(out)).toBe(true);
      expect(out).toContain("Authorization: Bearer");
    });
    it("redacts Basic credentials", () => {
      const out = redact("Authorization: Basic dXNlcjpwYXNzd29yZA==");
      expect(isRedacted(out)).toBe(true);
      expect(out).toContain("Authorization: Basic");
    });
    it("redacts Token auth", () => {
      expect(isRedacted(redact("Authorization: Token abc123defghijklmnop"))).toBe(true);
    });
    it("is case-insensitive for Authorization", () => {
      expect(isRedacted(redact("authorization: bearer eyJhbGci..."))).toBe(true);
    });
  });

  // ── curl -u ───────────────────────────────────────────────────────

  describe("curl -u user:pass", () => {
    it("redacts -u credentials", () => {
      const out = redact("curl -u admin:supersecret https://api.example.com");
      expect(isRedacted(out)).toBe(true);
      expect(out).toContain("curl");
    });
  });

  // ── AWS keys ──────────────────────────────────────────────────────

  describe("AWS keys", () => {
    it("redacts AWS_SECRET_ACCESS_KEY=value", () => {
      expect(isRedacted(redact("AWS_SECRET_ACCESS_KEY=abc123secretXYZlongvalue"))).toBe(true);
    });
    it("redacts aws_secret_access_key: value (lowercase)", () => {
      expect(isRedacted(redact("aws_secret_access_key: abc123secretXYZlongvalue"))).toBe(true);
    });
    it("redacts AWS_SESSION_TOKEN", () => {
      expect(isRedacted(redact("AWS_SESSION_TOKEN=FwoGZXIvYXdzE...verylongtoken"))).toBe(true);
    });
    it("redacts AKIA access key ID", () => {
      expect(isRedacted(redact("AKIAIOSFODNN7EXAMPLE"))).toBe(true);
    });
    it("redacts ASIA temporary key", () => {
      expect(isRedacted(redact("ASIAIOSFODNN7EXAMPLE"))).toBe(true);
    });
  });

  // ── GitHub tokens ─────────────────────────────────────────────────

  describe("GitHub tokens", () => {
    it("redacts ghp_ personal access token", () => {
      const tok = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabc";
      expect(isRedacted(redact("token = " + tok))).toBe(true);
    });
    it("redacts gho_ OAuth token", () => {
      const tok = "gho_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabc";
      expect(isRedacted(redact(tok))).toBe(true);
    });
    it("redacts github_pat_ fine-grained token", () => {
      const tok = "github_pat_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
      expect(isRedacted(redact(tok))).toBe(true);
    });
  });

  // ── OpenAI / Anthropic keys ───────────────────────────────────────

  describe("OpenAI / Anthropic / provider keys", () => {
    it("redacts sk-proj- key", () => {
      const tok = "sk-proj-" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabc";
      expect(isRedacted(redact(tok))).toBe(true);
    });
    it("redacts sk-ant- Anthropic key", () => {
      const tok = "sk-ant-" + "api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ";
      expect(isRedacted(redact(tok))).toBe(true);
    });
    it("redacts sk-live- key", () => {
      const tok = "sk-live-" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabc";
      expect(isRedacted(redact(tok))).toBe(true);
    });
    it("redacts generic sk- key", () => {
      const tok = "sk-" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabc";
      expect(isRedacted(redact("OPENAI_API_KEY=" + tok))).toBe(true);
    });
  });

  // ── Slack tokens ──────────────────────────────────────────────────

  describe("Slack tokens", () => {
    it("redacts xoxb- bot token", () => {
      // Build token at runtime so the literal never appears in source
      const tok = ["xoxb", "123456789", "ABCDEFGHIJKLMNOPQRSTUVWXYZabc"].join("-");
      expect(isRedacted(redact(tok))).toBe(true);
    });
    it("redacts xoxp- user token", () => {
      const tok = ["xoxp", "123456789", "ABCDEFGHIJKLMNOPQRSTUVWXYZabc"].join("-");
      expect(isRedacted(redact(tok))).toBe(true);
    });
  });

  // ── JSON-embedded secrets ─────────────────────────────────────────

  describe("JSON-embedded secrets", () => {
    it("redacts apiKey JSON field", () => {
      expect(isRedacted(redact('{ "apiKey": "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabc" }'))).toBe(true);
    });
    it("redacts api_key JSON field", () => {
      expect(isRedacted(redact('{ "api_key": "supersecretvalue123" }'))).toBe(true);
    });
    it("redacts secret JSON field", () => {
      expect(isRedacted(redact('{ "secret": "topsecretvalue1234" }'))).toBe(true);
    });
    it("redacts password JSON field", () => {
      expect(isRedacted(redact('{ "password": "hunter2password" }'))).toBe(true);
    });
    it("redacts token JSON field", () => {
      expect(isRedacted(redact('{ "token": "myauthtoken123456" }'))).toBe(true);
    });
    it("preserves the key name", () => {
      const out = redact('{ "apiKey": "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabc" }');
      expect(out).toContain('"apiKey"');
    });
    it("does not redact short/non-secret JSON values", () => {
      // Value < 8 chars shouldn't be matched
      expect(notRedacted(redact('{ "count": "three" }'))).toBe(true);
    });
  });

  // ── Generic key=value / key: value ───────────────────────────────

  describe("generic key=value patterns", () => {
    it("redacts password=value", () => {
      expect(isRedacted(redact("password=mysecretpassword"))).toBe(true);
    });
    it("redacts password = value (with spaces)", () => {
      expect(isRedacted(redact("password = mysecretpassword"))).toBe(true);
    });
    it("redacts secret: value", () => {
      expect(isRedacted(redact("secret: topsecretvalue"))).toBe(true);
    });
    it("redacts api_key=value", () => {
      expect(isRedacted(redact("api_key=abc123def456ghi789"))).toBe(true);
    });
    it("redacts api-key=value", () => {
      expect(isRedacted(redact("api-key=abc123def456ghi789"))).toBe(true);
    });
    it("preserves key label prefix", () => {
      const out = redact("password=mysecretpassword");
      expect(out).toContain("password");
    });
  });

  // ── High-entropy catch-all ────────────────────────────────────────

  describe("high-entropy string detection", () => {
    it("redacts a random-looking 32-char token", () => {
      // High entropy: mix of upper, lower, digits, symbols
      expect(isRedacted(redact("f3Kp9mXz2qL8nR5vT1wY6jB4hC0sA7eN"))).toBe(true);
    });
    it("does NOT redact short tokens under 20 chars", () => {
      expect(notRedacted(redact("abc123def456"))).toBe(true);
    });
    it("does NOT redact all-lowercase identifiers", () => {
      expect(notRedacted(redact("normalvariablename"))).toBe(true);
    });
    it("does NOT redact ALL_CAPS constant names", () => {
      expect(notRedacted(redact("MY_CONSTANT_VALUE_HERE"))).toBe(true);
    });
    it("does NOT redact camelCase identifiers", () => {
      expect(notRedacted(redact("normalizeMessageContent"))).toBe(true);
    });
    it("does NOT redact file paths", () => {
      expect(notRedacted(redact("/usr/local/lib/node_modules/package"))).toBe(true);
    });
  });

  // ── Multi-secret text ─────────────────────────────────────────────

  describe("multi-secret text", () => {
    it("redacts multiple secrets in one string", () => {
      const text = [
        "export AWS_SECRET_ACCESS_KEY=abc123secretXYZlongvalue",
        "export GITHUB_TOKEN=" + "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabc",
      ].join("\n");
      const out = redact(text);
      expect(out.match(/\[REDACTED\]/g)?.length).toBeGreaterThanOrEqual(2);
    });

    it("leaves non-sensitive text unchanged", () => {
      const safe = "const x = 42;\nconsole.log('hello world');";
      expect(redact(safe)).toBe(safe);
    });
  });

  // ── Idempotency ───────────────────────────────────────────────────

  describe("idempotency", () => {
    it("double-redacting produces the same result", () => {
      const text = "password=mysecretpassword";
      expect(redact(redact(text))).toBe(redact(text));
    });
  });
});
