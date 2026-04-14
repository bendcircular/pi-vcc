import { describe, it, expect } from "bun:test";
import { renderMessage } from "../src/core/render-entries";
import type { Message } from "@mariozechner/pi-ai";
import { userMsg, assistantText, assistantWithToolCall, toolResult } from "./fixtures";

describe("renderMessage", () => {
  it("renders user message", () => {
    const r = renderMessage(userMsg("hello"), 0);
    expect(r).toEqual({ index: 0, role: "user", summary: "hello" });
  });

  it("renders assistant text", () => {
    const r = renderMessage(assistantText("done"), 1);
    expect(r.role).toBe("assistant");
    expect(r.summary).toBe("done");
  });

  it("renders tool result", () => {
    const r = renderMessage(toolResult("Read", "file contents"), 2);
    expect(r.role).toBe("tool_result");
    expect(r.summary).toContain("[Read]");
  });

  it("renders tool call arguments with values", () => {
    const r = renderMessage(assistantWithToolCall("Read", { path: "a.ts" }), 2);
    expect(r.summary).toContain("Read(path=a.ts)");
  });

  it("renders error tool result with prefix", () => {
    const r = renderMessage(toolResult("bash", "not found", true), 3);
    expect(r.summary).toStartWith("ERROR");
  });

  it("truncates long user text", () => {
    const long = "x".repeat(500);
    const r = renderMessage(userMsg(long), 0);
    expect(r.summary.length).toBeLessThanOrEqual(300);
  });

  it("renders bashExecution message", () => {
    const msg = { role: "bashExecution", command: "ls -la", output: "total 0\n" } as any;
    const r = renderMessage(msg, 5);
    expect(r.role).toBe("bash");
    expect(r.summary).toContain("$ ls -la");
    expect(r.summary).toContain("total 0");
  });

  it("renders bashExecution with missing output", () => {
    const msg = { role: "bashExecution", command: "exit 1" } as any;
    const r = renderMessage(msg, 6);
    expect(r.role).toBe("bash");
    expect(r.summary).toContain("$ exit 1");
  });

  it("handles message with undefined content", () => {
    const msg = { role: "assistant", content: undefined } as any;
    const r = renderMessage(msg, 3);
    expect(r.role).toBe("assistant");
    expect(r.summary).toBe("");
  });

  // ── redaction in recall path ──

  it("redacts Bearer token in user message", () => {
    const tok = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.abc";
    const r = renderMessage(userMsg(`Authorization: Bearer ${tok}`), 0);
    expect(r.summary).toContain("[REDACTED]");
    expect(r.summary).not.toContain(tok);
  });

  it("redacts Bearer token in tool result", () => {
    const tok = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.abc";
    const r = renderMessage(toolResult("bash", `Authorization: Bearer ${tok}`), 1);
    expect(r.summary).toContain("[REDACTED]");
    expect(r.summary).not.toContain(tok);
  });

  it("redacts DSN credentials in user message", () => {
    const r = renderMessage(userMsg("postgres://dbuser:hunter2@db.example.com:5432/mydb"), 0);
    expect(r.summary).toContain("[REDACTED]");
    expect(r.summary).not.toContain("hunter2");
    expect(r.summary).toContain("db.example.com");
  });

  it("redacts bash command in bashExecution", () => {
    const msg = { role: "bashExecution", command: "curl -u admin:s3cr3t https://api.example.com", output: "ok" } as any;
    const r = renderMessage(msg, 0);
    expect(r.summary).toContain("[REDACTED]");
    expect(r.summary).not.toContain("s3cr3t");
  });

  it("does not redact safe content", () => {
    const r = renderMessage(userMsg("what does normalize.ts do?"), 0);
    expect(r.summary).toBe("what does normalize.ts do?");
  });
});

