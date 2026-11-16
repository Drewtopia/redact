import { scrub, mint, valuesIn, type MaskOptions, type Scan } from './vault.ts'

// Masking a tool's result: every string in it, keys included, plus its text
// and context. A value found only by its field name, or only in the result
// read as JSON, is put back where it sits in the result.

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
// `incomplete`, and the result is then withheld whole.
export function walk(value: unknown, fn: (s: string) => string, st: WalkState, depth = 0): unknown {
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

// What a tool gave back. `text` is read only when `isError` is set.
export type ToolOutput = { result?: unknown; text?: string; context?: string[]; isError?: boolean }

// Either why the result must be withheld, or the result masked. With no tags,
// nothing was found and the output can pass as it was. `error` is the masked
// error text of an errored result, when there is one to send.
export type MaskedOutput =
  | { withhold: string }
  | { tags: Set<string>; result: unknown; context?: string[]; error?: string }

// Scans the result three ways in one run: its fields as `name: value` lines,
// the whole result as JSON, and each string on its own. Throws when the scan
// fails, or when a value cannot be mapped back into the result safely; the
// caller withholds then.
export async function maskResult(scan: Scan, r: ToolOutput, mask: MaskOptions = {}): Promise<MaskedOutput> {
  const strings: string[] = []
  const st: WalkState = { incomplete: false }
  walk(r.result, (s) => (strings.push(s), s), st)
  // Part of the result could not be read (too deep, or not plain data), so
  // it was never scanned: withhold the whole result rather than pass it raw.
  if (st.incomplete) return { withhold: 'redact: part of this result could not be scanned (too deep, or not plain data), so it was withheld. Narrow the call and retry.' }
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
  const { masked, tags } = await scrub(scan, texts, mask)
  if (tags.size === 0) return { tags, result: r.result, context: r.context }

  const leaves = masked.slice(2)
  const lookup = new Map(unique.map((s, i) => [s, leaves[i] ?? s]))
  // Values this scan found with their field name, longest first. A placeholder
  // already in the result (a subagent's answer) was not found here.
  const inContext = [...valuesIn(masked[0] ?? '')].filter(([, t]) => tags.has(t))
  for (const [raw, tag] of valuesIn(masked[1] ?? '')) {
    if (!tags.has(tag)) continue
    // A match that cuts through JSON syntax cannot be mapped safely: this
    // throws, and the caller withholds the result.
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
  if (!inContext.every(placed)) return { withhold: 'redact: a hidden value in this result could not be put back in place, so the result was withheld. Narrow the call and retry.' }
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
  if (st2.incomplete) return { withhold: 'redact: a hidden value sits in a number in this result, which cannot hold a placeholder, so the result was withheld.' }
  const context = r.context?.map(fix)
  if (!r.isError) return { tags, result, context }
  // An errored result is sent on as a refusal: its masked text, or the result
  // itself when that is the error text.
  const error = r.text !== undefined ? fix(r.text) : typeof result === 'string' ? result : undefined
  return { tags, result, context, error }
}
