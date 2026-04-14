import type { Message } from "@mariozechner/pi-ai";
import { clip, textOf } from "./content";
import { summarizeToolArgs } from "./tool-args";
import { extractPath } from "./tool-args";
import { redact } from "./redact";

export interface RenderedEntry {
  index: number;
  role: string;
  summary: string;
  files?: string[];
}

const toolCalls = (content: Message["content"]): string => {
  if (!content || typeof content === "string") return "";
  return content
    .filter((c) => c.type === "toolCall")
    .map((c) => `${c.name}(${redact(summarizeToolArgs(c.arguments))})`)
    .join(", ");
};

const extractFilesFromContent = (content: Message["content"]): string[] => {
  if (!content || typeof content === "string") return [];
  return content
    .filter((c) => c.type === "toolCall")
    .map((c) => extractPath(c.arguments))
    .filter((p): p is string => p !== null);
};

export const renderMessage = (msg: Message, index: number, full = false): RenderedEntry => {
  if (msg.role === "user") {
    const redacted = redact(textOf(msg.content));
    return { index, role: "user", summary: full ? redacted : clip(redacted, 300) };
  }
  if (msg.role === "toolResult") {
    const prefix = msg.isError ? "ERROR " : "";
    const redacted = redact(textOf(msg.content));
    return {
      index, role: "tool_result",
      summary: `${prefix}[${msg.toolName}] ${full ? redacted : clip(redacted, 200)}`,
    };
  }
  // bashExecution has command+output instead of content
  if ((msg as any).role === "bashExecution") {
    const cmd = redact((msg as any).command ?? "");
    const out = redact((msg as any).output ?? "");
    const text = full ? `$ ${cmd}\n${out}` : clip(`$ ${cmd}\n${out}`, 300);
    return { index, role: "bash", summary: text };
  }
  const redacted = redact(textOf(msg.content));
  const text = full ? redacted : clip(redacted, 300);
  const tools = redact(toolCalls(msg.content));
  const files = extractFilesFromContent(msg.content);
  const summary = tools ? `${tools}\n${text}` : text;
  return { index, role: "assistant", summary, ...(files.length > 0 && { files }) };
};
