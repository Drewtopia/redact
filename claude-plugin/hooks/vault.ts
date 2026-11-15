// The placeholders of this session and the values behind them, and the scan:
// the redact binary finds what to hide (`redact scan --json`), this file swaps
// each part for a placeholder and remembers it, so a tool can get it back.
//
// The map lives in module memory, so a reload of the mod forgets it: a
// placeholder minted before the reload stays a placeholder from then on.

// The binary's own shape, `[LABEL-1a2b3c4d]`, so a placeholder reads the same
// whether redact ran in a pipe or here.
const TAG = /\[[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-[0-9a-f]{8}\]/g
// A placeholder read back from a file stands for its own text: it restores
// to that text, never to the value, so quoting one cannot leak the value.
const LITERAL = 'LITERAL'

const byValue = new Map<string, string>()
const byTag = new Map<string, string>()

// Texts are joined into one stdin, so a tool result costs one process. A
// rule cannot match across NUL plus two newlines; a span that does anyway is
// cut at the joins, so each side is still hidden.
const SEP = '\n\u0000\n'

// Below this a known value is not hidden again on sight: `Drew` hidden once
// in an Author line must not swallow every later `Drew`.
const ECHO_MIN = 8

function hex8(): string {
  const bytes = new Uint8Array(4)
  const crypto = (globalThis as { crypto?: { getRandomValues?: (b: Uint8Array) => Uint8Array } }).crypto
  if (crypto?.getRandomValues) crypto.getRandomValues(bytes)
  else for (let i = 0; i < 4; i++) bytes[i] = Math.floor(Math.random() * 256)
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

// A value that holds a placeholder from an earlier pass (a key inside a URL
// password) is stored with it put back, so one restore gives the real text.
export function mint(label: string, raw: string, tags: Set<string>): string {
  const value = label === LITERAL ? raw : restore(raw)
  let tag = byValue.get(value)
  if (!tag) {
    do tag = `[${label}-${hex8()}]`
    while (byTag.has(tag))
    byValue.set(value, tag)
    byTag.set(tag, value)
  }
  tags.add(tag)
  return tag
}

// One pass, on purpose: a LITERAL gives back placeholder text, and that text
// must not then turn into the value. `onValue` hears each real value put back.
export function restore(text: string, onValue?: (v: string) => void): string {
  if (byTag.size === 0 || !text.includes('[')) return text
  return text.replace(TAG, (t) => {
    const v = byTag.get(t)
    if (v === undefined) return t
    if (!isLiteral(t)) onValue?.(v)
    return v
  })
}

export const isLiteral = (tag: string): boolean => /^\[LITERAL-[0-9a-f]{8}\]$/.test(tag)

// The real value behind each live placeholder in `text`, with its placeholder.
// With `literals`, also each LITERAL tag with the placeholder text it escapes.
export function valuesIn(text: string, { literals = false } = {}): Map<string, string> {
  const out = new Map<string, string>()
  for (const t of text.match(TAG) ?? []) {
    const v = byTag.get(t)
    if (v !== undefined && (literals || !isLiteral(t))) out.set(v, t)
  }
  return out
}

function escapeLiteralTags(text: string, tags: Set<string>): string {
  if (byTag.size === 0 || !text.includes('[')) return text
  return text.replace(TAG, (t) => (byTag.has(t) && !isLiteral(t) ? mint(LITERAL, t, tags) : t))
}

// Hides values already hidden once wherever they turn up again, bare, where
// no rule fires: a tool that echoes a key it was handed must not print it.
// `extra` are values this call handed to a tool, hidden down to 4 characters.
// shortcut: one includes() per known value; index them if sessions reach many thousands.
function knownValues(extra: Set<string>): string[] {
  const known = [...byValue.keys()].filter((v) => v.length >= ECHO_MIN && !isLiteral(byValue.get(v)!))
  return [...new Set([...known, ...[...extra].filter((v) => v.length >= 4)])].sort((a, b) => b.length - a.length)
}

function hideKnown(text: string, all: string[], tags: Set<string>): string {
  let out = text
  for (const v of all) if (out.includes(v)) out = out.split(v).join(mint(labelOf(byValue.get(v)) ?? 'SECRET', v, tags))
  return out
}

// A command handed a value can print part of it (`cut -c1-12`, `${v:0:8}`),
// which no rule and no whole-value match finds. So any run of SLICE_MIN or
// more characters taken from a handed value is hidden too. An encoded form
// (base64, hex) still gets through.
const SLICE_MIN = 6
// Every value handed to a tool this session: a slice can come back later
// (`printf %s [SECRET-…] > f`, then `cut -c1-12 f`).
const handedEver = new Set<string>()
const KINDS = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/]
const WORD_MAX = 10

function hideSlices(text: string, v: string, tags: Set<string>): string {
  if (v.length < SLICE_MIN) return text
  const windows = new Map<string, number>()
  for (let i = 0; i + SLICE_MIN <= v.length; i++) {
    const w = v.slice(i, i + SLICE_MIN)
    if (!windows.has(w)) windows.set(w, i)
  }
  // Cheap check first: most output holds no part of the value.
  if (![...windows.keys()].some((w) => text.includes(w))) return text
  const label = labelOf(byValue.get(v)) ?? 'SECRET'
  let out = ''
  let p = 0
  while (p < text.length) {
    const i = p + SLICE_MIN <= text.length ? windows.get(text.slice(p, p + SLICE_MIN)) : undefined
    if (i === undefined) {
      out += text[p++]
      continue
    }
    let k = SLICE_MIN
    while (p + k < text.length && i + k < v.length && text[p + k] === v[i + k]) k++
    const run = text.slice(p, p + k)
    // One kind of character (`passwo`, `123456`) reads as a word or a
    // number, not a piece of a token: a human password must not hide every
    // later `password`.
    // A run of WORD_MAX or more is hidden whatever it holds: a passphrase
    // such as `correcthorsebattery` is one kind all through.
    if (run.length < WORD_MAX && KINDS.filter((re) => re.test(run)).length < 2) {
      out += text[p++]
      continue
    }
    out += mint(label, run, tags)
    p += k
  }
  return out
}

// A pack's label can be anything (`123-customers`, `v1.2`): fold it into the
// placeholder's shape. A label of LITERAL must not mint the hook's own tags.
function tagLabel(label: string): string {
  const t = label.toUpperCase().replace(/[^A-Z0-9]+/g, '-').replace(/^[-0-9]+|-+$/g, '') || 'HIDDEN'
  return t === LITERAL ? `${LITERAL}-LIST` : t
}

const labelOf = (tag: string | undefined): string | undefined => tag?.slice(1, -10)

type Span = { start: number; end: number; label: string }

// UTF-8 byte offsets (what the binary reports) to UTF-16 indexes (what a JS
// string slices by). A lone surrogate travels as U+FFFD, three bytes.
function byteIndexes(text: string, offsets: number[]): Map<number, number> {
  const map = new Map<number, number>()
  let bytes = 0
  let i = 0
  for (const w of [...new Set(offsets)].sort((x, y) => x - y)) {
    while (i < text.length && bytes < w) {
      const c = text.codePointAt(i) ?? 0
      bytes += c < 0x80 ? 1 : c < 0x800 ? 2 : c < 0x10000 ? 3 : 4
      i += c > 0xffff ? 2 : 1
    }
    map.set(w, i)
  }
  return map
}

function byteLength(text: string): number {
  let n = 0
  for (const ch of text) {
    const c = ch.codePointAt(0) ?? 0
    n += c < 0x80 ? 1 : c < 0x800 ? 2 : c < 0x10000 ? 3 : 4
  }
  return n
}

export type ScanOptions = {
  binary: string
  command?: string
  timeoutMs: number
  // Swap live placeholders in the text for LITERAL ones first: true for text
  // read from outside (a file, a log), false where placeholders are handles.
  escape?: boolean
  handed?: Set<string>
  // Called once with the reason when the binary cannot run, so the person
  // learns why everything is being withheld.
  onBroken?: (why: string) => void
  // Called with the full path when the bare name failed and locate found it.
  onLocated?: (path: string) => void
}

// Where installers put redact. A session started by an app or service that
// was running before redact was installed has a PATH without it, so when the
// bare name fails to start, these folders are tried before withholding.
// A configured path (one holding a slash) is used as given.
export async function locate($: any, name: string): Promise<string | undefined> {
  if (/[\\/]/.test(name)) return undefined
  const home = (await $.env.get('HOME')) ?? (await $.env.get('USERPROFILE'))
  const miseData = await $.env.get('MISE_DATA_DIR')
  const xdgData = await $.env.get('XDG_DATA_HOME')
  const localAppData = await $.env.get('LOCALAPPDATA')
  const cargoHome = await $.env.get('CARGO_HOME')
  const dirs = [
    miseData && `${miseData}/shims`,
    xdgData && `${xdgData}/mise/shims`,
    home && `${home}/.local/share/mise/shims`,
    localAppData && `${localAppData}/mise/shims`,
    cargoHome && `${cargoHome}/bin`,
    home && `${home}/.cargo/bin`,
    home && `${home}/.local/bin`,
    '/opt/homebrew/bin',
    '/usr/local/bin',
  ].filter((d): d is string => Boolean(d))
  for (const dir of dirs) {
    for (const file of [name, `${name}.exe`]) {
      if (await $.fs.exists(`${dir}/${file}`)) return `${dir}/${file}`
    }
  }
  return undefined
}

// Masks each text. Throws when the binary fails, so the hook withholds.
export async function scrub($: any, texts: string[], o: ScanOptions): Promise<{ masked: string[]; tags: Set<string> }> {
  const tags = new Set<string>()
  if (texts.length === 0) return { masked: [], tags }
  const pieces = o.escape ? texts.map((t) => escapeLiteralTags(t, tags)) : texts
  const joined = pieces.join(SEP)
  // An env var, not --command: a build too old to know it still runs.
  const exec = (binary: string) =>
    $.process.run([binary, 'scan', '--json'], { stdin: joined, timeoutMs: o.timeoutMs, ...(o.command ? { env: { REDACT_COMMAND: o.command } } : {}) })
  let r: { exitCode: number; stdout: string; stderr: string; isStdoutTruncated: boolean }
  try {
    r = await exec(o.binary)
  } catch (err) {
    const found = await locate($, o.binary).catch(() => undefined)
    try {
      if (!found) throw err
      r = await exec(found)
      o.onLocated?.(found)
    } catch {
      const why = `could not run \`${o.binary}\` (${err instanceof Error ? err.message : String(err)})`
      o.onBroken?.(why)
      throw new Error(why)
    }
  }
  if (r.exitCode !== 0 || r.isStdoutTruncated) {
    const why = `\`${o.binary} scan\` exit ${r.exitCode}: ${r.stderr.trim().split('\n')[0] ?? ''}`
    o.onBroken?.(why)
    throw new Error(why)
  }
  const spans: unknown = JSON.parse(r.stdout)
  // Spans of another shape would hide nothing and pass the text raw.
  const size = byteLength(joined)
  const ok = (s: any): s is Span =>
    Number.isInteger(s?.start) && Number.isInteger(s?.end) && s.start >= 0 && s.start < s.end && s.end <= size && typeof s.label === 'string'
  if (!Array.isArray(spans) || !spans.every(ok)) {
    const why = `\`${o.binary} scan --json\` printed spans of an unknown shape`
    o.onBroken?.(why)
    throw new Error(why)
  }
  const at = byteIndexes(joined, spans.flatMap((s) => [s.start, s.end]))

  // Each piece's spans, in piece-local UTF-16 indexes, cut at the joins.
  let pos = 0
  const parts = pieces.map((text) => {
    const part = { text, at: pos, spans: [] as Span[] }
    pos += text.length + SEP.length
    return part
  })
  for (const s of spans) {
    const a = at.get(s.start) ?? 0
    const b = at.get(s.end) ?? joined.length
    for (const p of parts) {
      const lo = Math.max(a, p.at)
      const hi = Math.min(b, p.at + p.text.length)
      if (lo < hi) p.spans.push({ start: lo - p.at, end: hi - p.at, label: s.label })
    }
  }

  const minted = parts.map(({ text, spans: list }) => {
    // Overlapping spans merge into one, under the first one's label.
    list.sort((x, y) => x.start - y.start || y.end - x.end)
    const merged: Span[] = []
    for (const s of list) {
      const last = merged[merged.length - 1]
      if (last && s.start < last.end) last.end = Math.max(last.end, s.end)
      else merged.push({ ...s })
    }
    let out = ''
    let cur = 0
    for (const s of merged) {
      const label = tagLabel(s.label)
      out += text.slice(cur, s.start) + mint(label, text.slice(s.start, s.end), tags)
      cur = s.end
    }
    out += text.slice(cur)
    return out
  })
  // Built once all pieces minted, so a value found in one is hidden in the rest.
  const handed = o.handed ?? new Set<string>()
  const all = knownValues(handed)
  for (const v of handed) if (v.length >= SLICE_MIN) handedEver.add(v)
  const hide = (t: string) => [...handedEver].reduce((s, v) => hideSlices(s, v, tags), hideKnown(t, all, tags))
  return { masked: minted.map(hide), tags }
}
