#!/usr/bin/env node

/**
 * Launch a local Cursor SDK agent pinned to grok-4.5 using the same harness
 * Conductor uses (Application Support @cursor/sdk + CURSOR_API_KEY).
 *
 * Env:
 *   CURSOR_API_KEY              required
 *   CONDUCTOR_INTERNAL_BIN_DIR  optional; defaults to Conductor app-support bin
 *   CONDUCTOR_CURSOR_SDK_REQUIRE_PATH  optional require root for @cursor/sdk
 *
 * Args:
 *   --worktree ABS_PATH
 *   --prompt-file ABS_PATH
 *   --fast true|false
 *   --name optional agent name
 */

import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomUUID } from "node:crypto";

function usage(exitCode = 2) {
  process.stderr.write(
    [
      "Usage: run-cursor-agent.mjs --worktree ABS_PATH --prompt-file ABS_PATH",
      "                            --fast true|false [--name NAME]",
      "",
    ].join("\n"),
  );
  process.exit(exitCode);
}

function parseArgs(argv) {
  const out = {
    worktree: "",
    promptFile: "",
    fast: null,
    name: "",
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = argv[i + 1];
    switch (arg) {
      case "--worktree":
        out.worktree = next ?? "";
        i += 1;
        break;
      case "--prompt-file":
        out.promptFile = next ?? "";
        i += 1;
        break;
      case "--fast":
        out.fast = next ?? "";
        i += 1;
        break;
      case "--name":
        out.name = next ?? "";
        i += 1;
        break;
      case "-h":
      case "--help":
        usage(0);
        break;
      default:
        process.stderr.write(`Unknown argument: ${arg}\n`);
        usage(2);
    }
  }
  return out;
}

function defaultConductorBinDir() {
  return path.join(
    os.homedir(),
    "Library",
    "Application Support",
    "com.conductor.app",
    "bin",
  );
}

function loadCursorSdk() {
  const binDir =
    process.env.CONDUCTOR_INTERNAL_BIN_DIR?.trim() || defaultConductorBinDir();
  const requireRoot =
    process.env.CONDUCTOR_CURSOR_SDK_REQUIRE_PATH?.trim() ||
    path.join(binDir, ".internal", "cursor-node-worker.mjs");

  if (!fs.existsSync(requireRoot)) {
    throw new Error(
      `Conductor Cursor harness not found at ${requireRoot}. Is Conductor.app installed?`,
    );
  }

  const require = createRequire(pathToFileURL(requireRoot).href);
  return require("@cursor/sdk");
}

function textFromContent(content) {
  if (typeof content === "string") {
    return content;
  }
  if (!Array.isArray(content)) {
    return "";
  }
  const parts = [];
  for (const block of content) {
    if (!block || typeof block !== "object") {
      continue;
    }
    if (block.type === "text" && typeof block.text === "string") {
      parts.push(block.text);
    }
  }
  return parts.join("");
}

function emitAssistantText(text) {
  if (!text) {
    return;
  }
  process.stdout.write(text);
  if (!text.endsWith("\n")) {
    process.stdout.write("\n");
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.worktree || !args.promptFile || args.fast === null) {
    usage(2);
  }
  if (args.fast !== "true" && args.fast !== "false") {
    process.stderr.write(`Invalid --fast value: ${args.fast}\n`);
    usage(2);
  }
  if (!path.isAbsolute(args.worktree) || !fs.statSync(args.worktree).isDirectory()) {
    throw new Error(`Worktree must be an existing absolute directory: ${args.worktree}`);
  }
  if (!path.isAbsolute(args.promptFile) || !fs.statSync(args.promptFile).isFile()) {
    throw new Error(`Prompt file must be an existing absolute file: ${args.promptFile}`);
  }

  const apiKey = process.env.CURSOR_API_KEY?.trim();
  if (!apiKey) {
    throw new Error(
      "CURSOR_API_KEY is not set. Export it or store it in Conductor provider settings.",
    );
  }

  const prompt = fs.readFileSync(args.promptFile, "utf8");
  if (!prompt.trim()) {
    throw new Error(`Prompt file is empty: ${args.promptFile}`);
  }

  const fastMode = args.fast === "true";
  const model = {
    id: "grok-4.5",
    params: [{ id: "fast", value: fastMode ? "true" : "false" }],
  };

  const { Agent } = loadCursorSdk();
  const agentId = `grok-agents-${randomUUID()}`;
  const name = args.name?.trim() || `grok-4.5 ${fastMode ? "fast" : "standard"}`;

  process.stderr.write(
    `[grok-agents] launching local Cursor agent model=grok-4.5 fast=${fastMode} cwd=${args.worktree} id=${agentId}\n`,
  );

  const agent = await Agent.create({
    agentId,
    apiKey,
    model,
    name,
    local: {
      cwd: args.worktree,
    },
  });

  try {
    const run = await agent.send(prompt, { model });
    process.stderr.write(`[grok-agents] run started id=${run.id}\n`);

    for await (const event of run.stream()) {
      if (!event || typeof event !== "object") {
        continue;
      }
      if (event.type === "assistant") {
        emitAssistantText(textFromContent(event.message?.content));
      } else if (event.type === "thinking" && typeof event.text === "string" && event.text) {
        process.stderr.write(`[grok-agents:thinking] ${event.text}\n`);
      } else if (event.type === "tool_call") {
        const status = event.status ?? "unknown";
        const toolName = event.name ?? "tool";
        if (status === "running") {
          process.stderr.write(`[grok-agents:tool] ${toolName} starting\n`);
        } else if (status === "error") {
          process.stderr.write(`[grok-agents:tool] ${toolName} error\n`);
        }
      } else if (event.type === "status" && event.status === "ERROR") {
        process.stderr.write(
          `[grok-agents] status error: ${event.message ?? "Cursor agent failed"}\n`,
        );
      }
    }

    const result = await run.wait();
    const status = result?.status ?? run.status;
    process.stderr.write(
      `[grok-agents] run finished status=${status} model=${run.model?.id ?? model.id}\n`,
    );

    if (status === "error") {
      throw new Error(run.result ?? result?.result ?? "Cursor Grok agent failed");
    }
    if (status === "cancelled") {
      throw new Error("Cursor Grok agent was cancelled");
    }
  } finally {
    agent.close();
  }
}

main().catch((err) => {
  const message = err instanceof Error ? err.message : String(err);
  process.stderr.write(`[grok-agents] ${message}\n`);
  process.exit(1);
});
