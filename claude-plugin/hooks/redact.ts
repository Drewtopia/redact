import type { Register, PromptContextBlock } from 'claude-code'
import { scrub, restore, isLiteral, type ScanOptions } from './vault.ts'

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
const HINT = 'Is redact installed? `mise use -g github:Drewtopia/redact`'
const WITHHELD = `redact could not scan this result, so it was withheld. Narrow the output (head, grep, offset) and retry. ${HINT}`
const BLOCK_WITHHELD = '[redact withheld this text: the scan failed]'

// Subagent answers hold placeholders the subagent used: they stay live.
const LIVE_TAG_TOOLS = new Set(['Agent', 'Task'])

// Attachments that carry text from outside the engine's own prose.
const OUTSIDE_TEXT = new Set(['file', 'edited_text_file', 'queued_command'])

// A shell command that writes into git history or posts to GitHub keeps its
// placeholders, so a commit message or issue body cannot carry a real value
// off the machine.
const PUBLISHES =
  /\bgit\b(?:[ \t]+-[cC][ \t]+\S+|[ \t]+--?[\w-]+(?:=\S+)?)*[ \t]+(?:commit|tag|notes|send-email)\b|\bgh[ \t]+(?:issue|pr|release|gist|discussion|api|repo[ \t]+(?:create|edit))\b/

// Claude Code's shell tools, each with the characters that make a restored
// value run as code in it. PowerShell also reads @ , % as syntax, curly
// quotes as quotes and en/em dashes as a parameter's dash.
const SHELL_ACTIVE: Record<string, RegExp> = {
  Bash: /[\s$`"'\\;&|<>()*?[\]{}#~]|[\x00-\x1f\x7f]/,
  PowerShell: /[\s$`"'\\;&|<>()*?[\]{}#~@,%\u2013-\u2015\u2018-\u201f]|[\x00-\x1f\x7f]/,
}

const MEDIA_FILE = /\.(?:png|jpe?g|gif|webp|bmp|tiff?|heic|pdf)$/i
const looksBinary = (text: string): boolean => {
  const head = text.slice(0, 8192)
  return head.includes('\u0000') || (head.match(/\uFFFD/g)?.length ?? 0) > 8
}

type WalkState = { incomplete: boolean }
const MAX_DEPTH = 64

// Every string in plain data. A part it cannot rewrite (too deep, not plain
// data) sets `incomplete`, and the hook then withholds the whole result.
function walk(value: unknown, fn: (s: string) => string, st: WalkState, depth = 0): unknown {
  if (typeof value === 'string') return fn(value)
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
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = walk(v, fn, st, depth + 1)
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
    const { masked, tags } = await run($, next, binary, unique, { ...scan, escape: !LIVE_TAG_TOOLS.has(e.tool) })
    if (tags.size === 0) return r

    const lookup = new Map(unique.map((s, i) => [s, masked[i] ?? s]))
    const fix = (s: string): string => lookup.get(s) ?? s
    const result = walk(r.result, fix, { incomplete: false })
    const n = countHidden(tags)
    if (notify && n > 0) $.ui.notice(e.tool_use_id, `redact: hid ${n} value(s)`)
    const context = r.context ? { context: r.context.map(fix) } : {}
    if (r.isError) return { isError: true as const, result, text: r.text === undefined ? undefined : fix(r.text), ...context }
    return { result, ...context } as typeof r
  }).catch(async ($, e, next) => {
    if (!next.called) return { deny: WITHHELD }
    const r = await next(e)
    if (r.isError) return { isError: true as const, result: WITHHELD, text: WITHHELD }
    return { deny: WITHHELD }
  })

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
    const escape = e.type === 'file' || e.type === 'edited_text_file'
    const outside = e.origin.kind !== 'engine' || OUTSIDE_TEXT.has(e.type)
    const { masked, tags } = await run($, next, binary, [r.text], { escape: escape && outside })
    return tags.size === 0 ? r : { text: masked[0] ?? BLOCK_WITHHELD }
  }).catch(() => ({ text: BLOCK_WITHHELD }))

  // 5. A file named with @ is read with no tool call, and its raw text is
  //    stored in the transcript whatever the model is shown. So a file that
  //    holds anything to hide is refused before it is read; the Read tool's
  //    result is scrubbed, so the model is pointed there.
  on('prompt.mention', async ($, e, next) => {
    let text: string
    try {
      const read = await $.fs.read(e.path)
      if (typeof read !== 'string') return next(e)
      text = read
    } catch {
      if (!(await $.fs.exists(e.path))) return next(e)
      if (MEDIA_FILE.test(e.path)) return next(e)
      return { deny: 'redact: could not check this file; ask Claude to Read it instead' }
    }
    if (looksBinary(text)) return next(e)
    const { tags } = await run($, next, binary, [text])
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
