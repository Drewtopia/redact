import { expect, test } from 'claude-code/testing'
import { maskResult } from '../hooks/result.ts'
import type { Scan, Span } from '../hooks/vault.ts'

// Fake values are built at run time so no key-shaped string sits in the repo.
const TOKEN = 'abc123' + 'def456ghi789'
const TAG = /\[SECRET-[0-9a-f]{8}\]/
const TAGS = new RegExp(TAG, 'g')

// The scan port with no process: `find` gives each text's spans directly.
const memoryScan = (find: (text: string) => Span[]): Scan => async (texts) => texts.map(find)

// A span for each match's first capture group that matched.
const finds = (re: RegExp) => (text: string): Span[] =>
  [...text.matchAll(new RegExp(re.source, re.flags + 'd'))].map((m) => {
    const [start, end] = m.indices!.slice(1).find((g) => g !== undefined)!
    return { start, end, label: 'SECRET' }
  })
// A rule that finds a value on sight, and one keyed on a field name.
const bare = finds(/TOKEN=(\w+)/g)
const byName = finds(/^password: (\S+)$|TOKEN=(\w+)/gm)

test('a result with nothing to hide comes back as it was', async () => {
  const output = { result: { stdout: 'ok', n: 3 }, context: ['fine'] }
  const m = await maskResult(memoryScan(() => []), output)
  if (!('tags' in m)) throw new Error(m.withhold)
  expect(m.tags.size).toBe(0)
})

test('every string in a result and its context is masked, keys included', async () => {
  const m = await maskResult(memoryScan(bare), {
    result: { stdout: `TOKEN=${TOKEN}`, list: [`TOKEN=${TOKEN}`], [`TOKEN=${TOKEN}`]: 1 },
    context: [`seen TOKEN=${TOKEN}`],
  })
  if (!('tags' in m)) throw new Error(m.withhold)
  const out = JSON.stringify(m)
  expect(out).not.toContain(TOKEN)
  expect(out.match(TAGS)?.length).toBe(4)
  expect(m.context?.[0]).toMatch(/^seen TOKEN=\[SECRET-[0-9a-f]{8}\]$/)
})

test('a value known only by its field name is masked where it sits', async () => {
  const m = await maskResult(memoryScan(byName), { result: { user: 'kim', password: TOKEN } })
  if (!('tags' in m)) throw new Error(m.withhold)
  expect((m.result as { password: string }).password).toMatch(new RegExp(`^${TAG.source}$`))
  expect((m.result as { user: string }).user).toBe('kim')
})

test('a multiline value found as JSON is hidden whole, past a token inside it', async () => {
  const password = `line one\nTOKEN=${TOKEN}\nline three`
  const scan = memoryScan((text) => [
    ...bare(text),
    ...finds(/"password":"((?:[^"\\]|\\.)*)"/g)(text),
  ])
  const m = await maskResult(scan, { result: { password } })
  if (!('tags' in m)) throw new Error(m.withhold)
  expect((m.result as { password: string }).password).toMatch(new RegExp(`^${TAG.source}$`))
})

test('a match crossing JSON fields withholds the result', async () => {
  const scan = memoryScan((text) => finds(/("a":"x","b":"y)/g)(text))
  const m = await maskResult(scan, { result: { a: 'x', b: 'y' } })
  if (!('withhold' in m)) throw new Error('expected a withhold')
  expect(m.withhold).toContain('withheld')
})

test('a short value inside one found by its field name cannot be placed, so it throws and the hook withholds', async () => {
  const scan = memoryScan((text) => [...finds(/^password: (\S+)$/gm)(text), ...finds(/^(ab)-/gm)(text)])
  const password = 'ab-' + 'xyzw-cd'
  await expect(maskResult(scan, { result: { password } })).rejects.toThrow('cannot be placed')
})

test('a value running from a name into its value cannot be put back, so the result is withheld', async () => {
  const scan = memoryScan((text) => finds(/^(user: kimberly)$/gm)(text))
  const m = await maskResult(scan, { result: { user: 'kimberly' } })
  expect('withhold' in m && m.withhold).toContain('could not be put back')
})

test('a result too deep to read is withheld before any scan', async () => {
  let deep: unknown = 'x'
  for (let i = 0; i < 70; i++) deep = { deep }
  let scanned = false
  const m = await maskResult(async (texts) => ((scanned = true), texts.map(() => [])), { result: deep })
  expect('withhold' in m && m.withhold).toContain('could not be scanned')
  expect(scanned).toBe(false)
})

test('a hidden value in a number withholds the result', async () => {
  const m = await maskResult(memoryScan(finds(/(?:^|: )(4111111111111111)$/gm)), { result: { card: 4111111111111111 } })
  expect('withhold' in m && m.withhold).toContain('number')
})

test('an errored result gives its masked error text', async () => {
  const m = await maskResult(memoryScan(bare), { result: 'failed', text: `bad TOKEN=${TOKEN}`, isError: true })
  if (!('tags' in m)) throw new Error(m.withhold)
  expect(m.error).toMatch(/^bad TOKEN=\[SECRET-[0-9a-f]{8}\]$/)
})

test('masking options pass through: a value the tool was handed is hidden bare', async () => {
  const handed = 'zq' + 'x9k2'
  const m = await maskResult(memoryScan(() => []), { result: `echo ${handed}` }, { handed: new Set([handed]) })
  if (!('tags' in m)) throw new Error(m.withhold)
  expect(m.result).toMatch(/^echo \[SECRET-[0-9a-f]{8}\]$/)
})

test('a match that ends inside a JSON escape withholds with a reason, and does not throw', async () => {
  // The JSON copy reads `…/_git/gadget-api\"`: a rule that takes the `\` ends mid-escape.
  const m = await maskResult(memoryScan(finds(/_git\/([^/\s"'?#]+)/g)), { result: { stdout: 'x/_git/gadget-api"' } })
  if (!('withhold' in m)) throw new Error('expected a withhold')
  expect(m.withhold).toContain('JSON')
})

test('a short value found in a URL is placed where its own string already hid it', async () => {
  const url = 'https://dev.azure.com/fabrikamqa/Ops/_git/widget-api'
  const project = finds(/dev\.azure\.com\/[^/\s"'\\]+\/([^/\s"'?#\\]+)/g)
  const m = await maskResult(memoryScan(project), { result: { stdout: `${url}\n`, other: 'Opsware' } })
  if (!('tags' in m)) throw new Error(m.withhold)
  const out = m.result as { stdout: string; other: string }
  expect(out.stdout).toMatch(/^https:\/\/dev\.azure\.com\/fabrikamqa\/\[SECRET-[0-9a-f]{8}\]\/_git\/widget-api\n$/)
  // A short value is never replaced by blind substring.
  expect(out.other).toBe('Opsware')
})

// A hit under a name label that cannot be placed is dropped; a credential
// that cannot be placed still withholds the result.
const labelled = (label: string, re: RegExp) => (text: string): Span[] => finds(re)(text).map((s) => ({ ...s, label }))
const PASS = 's3cr3t' + '-pass-77'
const ANY = /\[[A-Z][A-Z0-9-]*-[0-9a-f]{8}\]/

test('a name running from a field name into its value is dropped, and the result passes', async () => {
  const m = await maskResult(memoryScan(labelled('PERSON', /^(user: marisol)$/gm)), { result: { user: 'marisol' } })
  if (!('tags' in m)) throw new Error(m.withhold)
  expect((m.result as { user: string }).user).toBe('marisol')
})

test('a JSON-view email that took the n of a line break is dropped, and the string hides its own copy', async () => {
  const mail = 'robin' + '@fabrikamq.example'
  const m = await maskResult(memoryScan(labelled('EMAIL', /([\w.]+@fabrikamq\.example)/g)), { result: { stdout: `a@fabrikamq.example\n${mail}\n` } })
  if (!('tags' in m)) throw new Error(m.withhold)
  const out = (m.result as { stdout: string }).stdout
  expect(out).not.toContain(mail)
  expect(out).toMatch(new RegExp(`^${ANY.source}\\n${ANY.source}\\n$`))
})

test('a JSON-view credential that took the n of a line break still withholds', async () => {
  const m = await maskResult(memoryScan(labelled('SECRET', /(\w*tok-[A-Z]{8})/g)), { result: { stdout: 'a\ntok-QWERTYUI\n' } })
  expect('withhold' in m && m.withhold).toContain('could not be put back')
})

test('a name match that ends inside a JSON escape is dropped, and the result passes', async () => {
  const m = await maskResult(memoryScan(labelled('REPO', /_git\/([^/\s"'?#]+)/g)), { result: { stdout: 'x/_git/gizmo-web"' } })
  if (!('tags' in m)) throw new Error(m.withhold)
})

test('a credential found by name is masked while a name beside it is dropped', async () => {
  const scan = memoryScan((text) => [...labelled('PERSON', /^(user: marisol)$/gm)(text), ...labelled('SECRET', /^password: (\S+)$/gm)(text)])
  const m = await maskResult(scan, { result: { user: 'marisol', password: PASS } })
  if (!('tags' in m)) throw new Error(m.withhold)
  expect(JSON.stringify(m.result)).not.toContain(PASS)
  expect((m.result as { password: string }).password).toMatch(new RegExp(`^${TAG.source}$`))
})

test('a credential seen on sight in one string is masked while a name elsewhere is dropped', async () => {
  const scan = memoryScan((text) => [...labelled('PERSON', /^(user: marisol)$/gm)(text), ...labelled('SECRET', /key=(\w{12,})/g)(text)])
  const key = 'Zq7' + 'xW2mK9pL4'
  const m = await maskResult(scan, { result: { user: 'marisol', note: `key=${key}` } })
  if (!('tags' in m)) throw new Error(m.withhold)
  expect(JSON.stringify(m.result)).not.toContain(key)
})

test('a name span merged over a credential found by field name withholds', async () => {
  // In the name: value view the PERSON span runs into the password and the two
  // merge under PERSON; no string's own scan sees the password.
  const scan = memoryScan((text) => [...labelled('PERSON', /(lee\npassword: s3cr)/g)(text), ...labelled('SECRET', /^password: (\S+)$/gm)(text)])
  const m = await maskResult(scan, { result: { user: 'lee', password: PASS } })
  expect('withhold' in m && m.withhold).toContain('could not be put back')
})

test('a name span merged over a credential in the JSON view withholds', async () => {
  // Its own value: one hidden in an earlier test would be hidden on sight.
  const pass = 'k8v' + '-merged-json-1'
  const scan = memoryScan((text) => [...labelled('PROJECT', /("b":"k8v)/g)(text), ...labelled('SECRET', /"b":"([^"]+)"/g)(text)])
  const m = await maskResult(scan, { result: { a: 'x', b: pass } })
  expect('withhold' in m && m.withhold).toContain('withheld')
})

test('a hit under a renamed or custom label counts as a credential', async () => {
  const m = await maskResult(memoryScan(labelled('HIDDEN', /^(user: oluwaseun)$/gm)), { result: { user: 'oluwaseun' } })
  expect('withhold' in m && m.withhold).toContain('could not be put back')
})

test('a short name inside a password found by field name leaves the password hidden whole', async () => {
  const scan = memoryScan((text) => [...labelled('SECRET', /^password: (\S+)$/gm)(text), ...labelled('PROJECT', /^(cd)-/gm)(text)])
  const password = 'cd-' + 'qrst-uv'
  const m = await maskResult(scan, { result: { password } })
  if (!('tags' in m)) throw new Error(m.withhold)
  expect((m.result as { password: string }).password).toMatch(new RegExp(`^${TAG.source}$`))
})

test('a name in a number stays as it is, and the result passes', async () => {
  const m = await maskResult(memoryScan(labelled('ID', /(?:^|: )(48213377)$/gm)), { result: { id: 48213377 } })
  if (!('tags' in m)) throw new Error(m.withhold)
  expect((m.result as { id: number }).id).toBe(48213377)
})

test('a remembered credential that sits in no string still withholds, with no rule firing this time', async () => {
  // Hidden once as a credential, then met again only in the name: value view,
  // where it runs from the field name into the value.
  const value = 'note: ' + 'r7w-remembered-9'
  await maskResult(memoryScan(labelled('SECRET', /^(note: \S+)$/gm)), { result: value })
  const m = await maskResult(memoryScan(() => []), { result: { note: value.slice(6) } })
  expect('withhold' in m && m.withhold).toContain('could not be put back')
})
