import type { Message } from "@mariozechner/pi-ai";
import type { NormalizedBlock } from "../types";
import { textOf } from "./content";
import { sanitize } from "./sanitize";
import { redact } from "./redact";

const normalizeOne = (msg: Message, msgIndex: number): NormalizedBlock[] => {
  if (msg.role === "user") {
    const blocks: NormalizedBlock[] = [];
    const text = redact(sanitize(textOf(msg.content)));
    if (text) blocks.push({ kind: "user", text, sourceIndex: msgIndex });
    if (msg.content && typeof msg.content !== "string") {
      for (const part of msg.content) {
        if (part.type === "image") {
          blocks.push({ kind: "user", text: `[image: ${part.mimeType}]`, sourceIndex: msgIndex });
        }
      }
    }
    return blocks.length > 0 ? blocks : [{ kind: "user", text: "", sourceIndex: msgIndex }];
  }

  if (msg.role === "toolResult") {
    return [{
      kind: "tool_result",
      name: msg.toolName,
      text: redact(sanitize(textOf(msg.content))),
      isError: msg.isError,
      sourceIndex: msgIndex,
    }];
  }

  if (msg.role === "assistant") {
    if (!msg.content) return [];
    if (typeof msg.content === "string") {
      return [{ kind: "assistant", text: redact(sanitize(msg.content)), sourceIndex: msgIndex }];
    }

    const blocks: NormalizedBlock[] = [];
    for (const part of msg.content) {
      if (part.type === "text") {
        blocks.push({ kind: "assistant", text: redact(sanitize(part.text)), sourceIndex: msgIndex });
      } else if (part.type === "thinking") {
        const sanitizedThinking = sanitize(part.thinking);
        const thinkingText = redact(sanitizedThinking);
        blocks.push({
          kind: "thinking",
          text: thinkingText,
          redacted: (part.redacted ?? false) || thinkingText !== sanitizedThinking,
          sourceIndex: msgIndex,
        });
      } else if (part.type === "toolCall") {
        blocks.push({
          kind: "tool_call",
          name: part.name,
          args: part.arguments,
          sourceIndex: msgIndex,
        });
      }
    }
    return blocks;
  }

  return [];
};

export const normalize = (messages: Message[]): NormalizedBlock[] =>
  messages.flatMap((msg, i) => normalizeOne(msg, i));


