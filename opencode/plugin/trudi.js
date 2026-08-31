/**
 * TRUDI OpenCode plugin — a thin adapter, deliberately free of logic.
 *
 * Every event is translated into the stdin-JSON contract of the Claude Code
 * hooks in claude/hooks/ and the corresponding Python hook is spawned. The
 * Python hooks remain the single source of truth (and the unit-tested
 * surface); this file only maps names and shapes:
 *
 *   tool.execute.before  → guard_pretooluse.py   (deny ⇒ throw = blocked)
 *   tool.execute.after   → log_narration.py      (fire-and-forget)
 *   chat.message         → log_user_message.py   (fire-and-forget)
 *   event session.idle   → forensic_audit.py     (fire-and-forget)
 *
 * Fail-open everywhere except an explicit guard deny: any spawn/parse error
 * must never break the session (mirrors the Python hooks' own posture).
 * Installed as a symlink: ~/.config/opencode/plugin/trudi.js → this file.
 */
import { spawn } from "node:child_process"
import { realpathSync } from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"

// Resolve through the install symlink so HOOKS points into the repo checkout.
const SELF = realpathSync(fileURLToPath(import.meta.url))
const REPO = path.resolve(path.dirname(SELF), "..", "..")
const HOOKS = path.join(REPO, "claude", "hooks")
const PYTHON = process.env.TRUDI_HOOK_PYTHON || "python3"

// OpenCode tool name → Claude Code tool name (the hooks' vocabulary).
const TOOL_MAP = {
  bash: "Bash",
  edit: "Edit",
  write: "Write",
  read: "Read",
  grep: "Grep",
  glob: "Glob",
  patch: "Edit",
}

// OpenCode args → Claude Code tool_input field names.
function mapArgs(ocTool, args) {
  const a = args || {}
  if (ocTool === "bash") return { command: a.command || "" }
  const out = { ...a }
  if (a.filePath !== undefined) {
    out.file_path = a.filePath
    delete out.filePath
  }
  return out
}

function runHook(script, payload) {
  return new Promise((resolve) => {
    try {
      const p = spawn(PYTHON, [path.join(HOOKS, script)], {
        stdio: ["pipe", "pipe", "ignore"],
      })
      let stdout = ""
      p.stdout.on("data", (d) => (stdout += d))
      p.on("error", () => resolve(""))
      p.on("close", () => resolve(stdout))
      p.stdin.write(JSON.stringify(payload))
      p.stdin.end()
    } catch {
      resolve("")
    }
  })
}

export const TrudiHooks = async ({ directory }) => {
  const cwd = directory || process.cwd()
  // tool args cached from the before hook, keyed by callID, for the after hook.
  const argCache = new Map()

  return {
    "tool.execute.before": async (input, output) => {
      const tool = TOOL_MAP[input.tool]
      if (!tool) return
      const tool_input = mapArgs(input.tool, output.args)
      if (input.callID) {
        argCache.set(input.callID, { tool, tool_input })
        if (argCache.size > 256) argCache.delete(argCache.keys().next().value)
      }
      const out = await runHook("guard_pretooluse.py", {
        hook_event_name: "PreToolUse",
        session_id: input.sessionID,
        cwd,
        tool_name: tool,
        tool_input,
      })
      if (!out.trim()) return
      try {
        const d = JSON.parse(out).hookSpecificOutput
        if (d && d.permissionDecision === "deny") {
          throw new Error(d.permissionDecisionReason || "blocked by TRUDI guard")
        }
      } catch (e) {
        if (e instanceof SyntaxError) return // unparseable ⇒ fail open
        throw e
      }
    },

    "tool.execute.after": async (input, output) => {
      const cached = argCache.get(input.callID) || {
        tool: TOOL_MAP[input.tool],
        tool_input: {},
      }
      argCache.delete(input.callID)
      if (!cached.tool) return
      await runHook("log_narration.py", {
        hook_event_name: "PostToolUse",
        session_id: input.sessionID,
        cwd,
        tool_name: cached.tool,
        tool_input: cached.tool_input,
        tool_response: { output: (output && output.output) || "" },
      })
    },

    "chat.message": async (_input, output) => {
      try {
        const msg = output && output.message
        if (!msg || msg.role !== "user") return
        const prompt = (output.parts || [])
          .filter((p) => p.type === "text" && typeof p.text === "string")
          .map((p) => p.text)
          .join("\n")
        if (!prompt.trim()) return
        await runHook("log_user_message.py", {
          hook_event_name: "UserPromptSubmit",
          session_id: msg.sessionID,
          cwd,
          prompt,
        })
      } catch {
        /* fail open */
      }
    },

    event: async ({ event }) => {
      try {
        if (!event || event.type !== "session.idle") return
        await runHook("forensic_audit.py", {
          hook_event_name: "Stop",
          session_id:
            (event.properties && event.properties.sessionID) || undefined,
          cwd,
        })
      } catch {
        /* fail open */
      }
    },
  }
}
