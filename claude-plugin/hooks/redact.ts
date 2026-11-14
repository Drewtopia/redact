import type { Register, PromptContextBlock } from 'claude-code'
import { scrub, restore, isLiteral, valuesIn, type ScanOptions } from './vault.ts'

// redact for Claude Code: every text that enters the conversation goes
// through the redact binary first, and the real value behind a placeholder
// goes back into a tool that runs on this machine.
//
// The event wiring follows transcript-redactor by Ray Amjad (MIT,
// github.com/ray-amjad/claude-code-mods), with its detector swapped for redact.
//
// Every hook fails closed: a hook that throws is skipped by the engine, which
// for a redactor means the raw text goes through. So each has a `.catch` that
// withholds instead.

const SCAN_CAP = 16_000_000
const HINT = "Is `redact` on this session's PATH? Install it with `mise use -g github:Drewtopia/redact`, or set the mod's `binary` option to its full path."
const WITHHELD = `redact could not scan this result, so it was withheld. Narrow the output (head, grep, offset) and retry. ${HINT}`
const BLOCK_WITHHELD = '[redact withheld this text: the scan failed]'

// Subagent answers hold placeholders the subagent used: they stay live.
const LIVE_TAG_TOOLS = new Set(['Agent', 'Task'])

// A shell command that writes into git history or posts to GitHub, GitLab or
// Azure DevOps keeps its placeholders, so a commit message or issue body
// cannot carry a real value off the machine.
const PUBLISHES =
  /\bgit\b(?:[ \t]+-[cC][ \t]+(?:"[^"]*"|'[^']*'|\S+)|[ \t]+--?[\w-]+(?:=\S+)?)*[ \t]+(?:commit|tag|notes|send-email)\b|\bgh[ \t]+(?:issue|pr|release|gist|discussion|api|repo[ \t]+(?:create|edit))\b|\bglab[ \t]+(?:issue|mr|release|snippet|api)\b|\baz[ \t]+(?:repos|boards|devops|pipelines|rest)\b/

// Claude Code's shell tools, each with the characters that make a restored
// value run as code in it. PowerShell also reads @ , % as syntax, curly
// quotes as quotes and en/em dashes as a parameter's dash.
const SHELL_ACTIVE: Record<string, RegExp> = {
  Bash: /[\s$`"'\\;&|<>()*?[\]{}#~]|[\x00-\x1f\x7f]/,
  PowerShell: /[\s$`"'\\;&|<>()*?[\]{}#~@,%\u2013-\u2015\u2018-\u201f]|[\x00-\x1f\x7f]/,
}

const MEDIA_FILE = /\.(?:png|jpe?g|gif|webp|bmp|tiff?|heic|pdf)$/i

type WalkState = { incomplete: boolean }
const MAX_DEPTH = 64
const CONTEXT_MAX = 1024

// `name: value` for each short one-line field, so a rule keyed on the field
// name (`password: …`) still fires on a value stored apart from its name.
function fields(value: unknown, out: string[] = [], depth = 0): string[] {
  if (value === null || typeof value !== 'object' || depth >= MAX_DEPTH) return out
  for (const [k, v] of Object.entries(value)) {
    if (typeof v === 'string' || typeof v === 'number' || typeof v === 'bigint') {
      const line = `${k}: ${v}`
      if (line.length <= CONTEXT_MAX && !line.includes('\n')) out.push(line)
    } else fields(v, out, depth + 1)
  }
  return out
}

// Every string in plain data, object keys included. A part it cannot rewrite
// (too deep, not plain data, a number that holds a hidden value) sets
// `incomplete`, and the hook then withholds the whole result.
function walk(value: unknown, fn: (s: string) => string, st: WalkState, depth = 0): unknown {
  if (typeof value === 'string') return fn(value)
  if (typeof value === 'number' || typeof value === 'bigint') {
    if (fn(String(value)) !== String(value)) st.incomplete = true
    return value
  }
  if (value === null || typeof value !== 'object') return value
  if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) return value
  if (depth >= MAX_DEPTH) {
    st.incomplete = true
    return value
  }
  if (Array.isArray(value)) return value.map((v) => walk(v, fn, st, depth + 1))
  const proto = Object.getPrototypeOf(value)
  if (proto !== Object.prototype && proto !== null) {
    st.incomplete = true
    return value
  }
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[fn(k)] = walk(v, fn, st, depth + 1)
  return out
}

type Budget = { budget: { remainingMs: number } }

const countHidden = (tags: Set<string>): number => [...tags].filter((t) => !isLiteral(t)).length

let warned = false

// Masks `texts` in one run of the binary, inside the hook's time budget.
async function run($: any, next: Budget, binary: string, texts: string[], extra: Partial<ScanOptions> = {}) {
  if (texts.some((t) => t.length > SCAN_CAP)) throw new Error('redact: text too large to scan')
  const timeoutMs = next.budget.remainingMs - 300
  if (timeoutMs < 200) throw new Error('redact: out of time')
  return scrub($, texts, {
    binary,
    timeoutMs,
    ...extra,
    onBroken: (why) => {
      if (warned) return
      warned = true
      try { $.ui.toast(`redact: ${why}. Withholding text until it runs. ${HINT}`) } catch {}
    },
  })
}

export const register: Register = (on, options) => {
  const opts = options as Record<string, unknown>
  const binary = String(opts.binary || 'redact')
  const notify = opts.notify !== false && opts.notify !== 'false'
  const restoreTools = new Set(
    String(opts.restoreTools ?? 'Bash,PowerShell,Write,Edit,MultiEdit,NotebookEdit,Read,Glob,Grep')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
  )

  // 1. What the person types, and context a hook above attached to it.
  on('prompt.submit', async ($, e, next) => {
    const context = e.context ?? []
    const { masked, tags } = await run($, next, binary, [e.text, ...context])
    if (tags.size === 0) return next(e)
    const n = countHidden(tags)
    if (n > 0 && notify) $.ui.toast(`redact: hid ${n} value(s) from the prompt`)
    return next({ ...e, text: masked[0] ?? '', ...(e.context ? { context: masked.slice(1) } : {}) })
  }).catch(($, e, next) => (next.called ? next(e) : { drop: `redact failed to scan this prompt, so it was not sent. ${HINT}` }))

  // 2. Every tool call. In: a placeholder becomes its real value, only for a
  //    tool that runs on this machine. Out: result, text and context.
  on('tool.call', async ($, e, next) => {
    const command = e.tool in SHELL_ACTIVE ? (e as { command?: unknown }).command : undefined
    const publishes = typeof command === 'string' && PUBLISHES.test(command)
    const isLocal = restoreTools.has(e.tool) && !publishes
    // Real values this call was handed: whatever the tool prints of them
    // comes back hidden, even bare and short, where no rule would fire.
    const handed = new Set<string>()
    const input = isLocal ? (walk({ ...e }, (s) => restore(s, (v) => handed.add(v)), { incomplete: false }) as typeof e) : e
    const active = SHELL_ACTIVE[e.tool]
    if (active && [...handed].some((v) => active.test(v))) {
      return {
        deny: 'redact: a value in this command holds shell characters, so it was not put into the shell, where it could run as code. Write it to a file with the Write tool and have the command read that file instead.',
      }
    }
    const r = await next(input)
    const scan = { command: typeof command === 'string' ? command : undefined, handed }
    if (r.deny !== undefined) {
      // A refusal from beneath may quote the input it refused, real values and all.
      const d = await run($, next, binary, [r.deny], { ...scan, escape: true })
      return d.tags.size === 0 ? r : { deny: d.masked[0] ?? WITHHELD }
    }

    const strings: string[] = []
    const st: WalkState = { incomplete: false }
    walk(r.result, (s) => (strings.push(s), s), st)
    // Part of the result could not be read (too deep, or not plain data), so
    // it was never scanned: withhold the whole result rather than pass it raw.
    if (st.incomplete) return { deny: 'redact: part of this result could not be scanned (too deep, or not plain data), so it was withheld. Narrow the call and retry.' }
    if (r.text !== undefined) strings.push(r.text)
    for (const c of r.context ?? []) strings.push(c)
    const unique = [...new Set(strings)]
    const named = fields(r.result).join('\n')
    const texts = named ? [named, ...unique] : unique
    const { masked, tags } = await run($, next, binary, texts, { ...scan, escape: !LIVE_TAG_TOOLS.has(e.tool) })
    if (tags.size === 0) return r

    const leaves = named ? masked.slice(1) : masked
    const lookup = new Map(unique.map((s, i) => [s, leaves[i] ?? s]))
    // Values this scan found with their field name, longest first. A placeholder
    // already in the result (a subagent's answer) was not found here.
    const inContext = named ? [...valuesIn(masked[0] ?? '')].filter(([, t]) => tags.has(t)).sort(([a], [b]) => b.length - a.length) : []
    // One that sits in no single string (it ran from a name into its value) cannot be put back.
    const placed = ([v]: [string, string]) => unique.some((s) => s === v || (v.length >= 4 && s.includes(v)))
    if (!inContext.every(placed)) return { deny: 'redact: a hidden value in this result could not be put back in place, so the result was withheld. Narrow the call and retry.' }
    const fix = (s: string): string => {
      let out = lookup.get(s) ?? s
      for (const [v, tag] of inContext) out = out === v ? tag : v.length >= 4 ? out.split(v).join(tag) : out
      return out
    }
    const st2: WalkState = { incomplete: false }
    const result = walk(r.result, fix, st2)
    if (st2.incomplete) return { deny: 'redact: a hidden value sits in a number in this result, which cannot hold a placeholder, so the result was withheld.' }
    const n = countHidden(tags)
    if (notify && n > 0) $.ui.notice(e.tool_use_id, `redact: hid ${n} value(s)`)
    const context = r.context ? { context: r.context.map(fix) } : {}
    if (r.isError) return { isError: true as const, result, text: r.text === undefined ? undefined : fix(r.text), ...context }
    return { result, ...context } as typeof r
  // A refusal, never a result: a string where the tool's output object goes
  // breaks its shape.
  }).catch(() => ({ deny: WITHHELD }))

  // 3. The blocks on the first message: CLAUDE.md and the engine's context.
  on('prompt.context', async ($, e, next) => {
    const r = await next(e)
    const { masked, tags } = await run($, next, binary, r.blocks.map((b) => b.text))
    if (tags.size === 0) return r
    // The raw files behind a rewritten CLAUDE.md would carry the value on to
    // the hooks above, so they are left out once any block changed.
    const blocks: PromptContextBlock[] = r.blocks.map((b, i) => ({ ...b, text: masked[i] ?? BLOCK_WITHHELD }))
    return { blocks }
  }).catch(async ($, e, next) => {
    const r = await next(e)
    return { blocks: r.blocks.map((b) => ({ ...b, text: BLOCK_WITHHELD })) }
  })

  // 4. What the engine injects after the first message: an @-file, a diff of
  //    a file that changed on disk, a nested CLAUDE.md, a hook's context.
  on('prompt.attachment', async ($, e, next) => {
    const r = await next(e)
    if (r.text == null) return r
    // File text: a placeholder in it stands for its own text, never the value.
    const escape = e.type === 'file' || e.type === 'edited_text_file'
    const { masked, tags } = await run($, next, binary, [r.text], { escape })
    return tags.size === 0 ? r : { text: masked[0] ?? BLOCK_WITHHELD }
  }).catch(() => ({ text: BLOCK_WITHHELD }))

  // 5. A file named with @ is read with no tool call, and its raw text is
  //    stored in the transcript whatever the model is shown. So a file that
  //    holds anything to hide is refused before it is read; the Read tool's
  //    result is scrubbed, so the model is pointed there.
  on('prompt.mention', async ($, e, next) => {
    if (MEDIA_FILE.test(e.path)) return next(e)
    let text: string
    try {
      text = await $.fs.read(e.path)
    } catch {
      if (!(await $.fs.exists(e.path))) return next(e)
      return { deny: 'redact: could not check this file; ask Claude to Read it instead' }
    }
    // UTF-16 text reads as UTF-8 with a NUL beside each ASCII character.
    const { tags } = await run($, next, binary, [text.replaceAll('\u0000', '')])
    if (tags.size > 0) return { deny: 'redact: this file holds something to hide; ask Claude to Read it instead, so those parts come back as placeholders' }
    return next(e)
  }).catch(($, e, next) => (next.called ? next(e) : { deny: 'redact: could not check this file' }))

  // 6. A subagent's task: a second layer for a value that reached the prompt
  //    some other way. A workflow agent's prompt can only be refused.
  on('agent.spawn', async ($, e, next) => {
    const { masked, tags } = await run($, next, binary, [e.prompt, e.description])
    if (tags.size === 0) return next(e)
    if (e.workflow) return { deny: "redact: this workflow agent's prompt holds something to hide, and a workflow prompt cannot be rewritten. Pass the value by a file or an env var instead." }
    return next({ ...e, prompt: masked[0] ?? '', description: masked[1] ?? '' })
  }).catch(($, e, next) => (next.called ? next(e) : { deny: 'redact failed to scan this task, so the subagent was not started.' }))
}
