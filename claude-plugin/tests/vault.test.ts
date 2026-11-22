import { expect, test } from 'claude-code/testing'
import { binaryScan, restore, scrub, ScanFailed, type Scan, type Span } from '../hooks/vault.ts'

// Fake values are built at run time so no key-shaped string sits in the repo.
const TOKEN = 'abc123' + 'def456ghi789'
const TAG = /\[SECRET-[0-9a-f]{8}\]/

// The scan port with no process: `find` gives each text's spans directly.
const memoryScan = (find: (text: string) => Span[]): Scan => async (texts) => texts.map(find)

// Hides the value after TOKEN= or PASSWORD=, in UTF-16 indexes.
const named = (label = 'SECRET') => (text: string): Span[] =>
  [...text.matchAll(/(?:TOKEN|PASSWORD)=(\S+)/g)].map((m) => {
    const start = (m.index ?? 0) + m[0].length - m[1]!.length
    return { start, end: start + m[1]!.length, label }
  })
const none = () => []

test('each text is masked, and a value keeps its placeholder across texts and calls', async () => {
  const scan = memoryScan(named())
  const { masked, tags } = await scrub(scan, [`TOKEN=${TOKEN}`, 'plain', `PASSWORD=${TOKEN}`])
  const tag = masked[0]!.slice('TOKEN='.length)
  expect(tag).toMatch(TAG)
  expect(masked).toEqual([`TOKEN=${tag}`, 'plain', `PASSWORD=${tag}`])
  expect([...tags]).toEqual([tag])
  expect(restore(masked[2]!)).toBe(`PASSWORD=${TOKEN}`)
  expect((await scrub(scan, [`TOKEN=${TOKEN}`])).masked[0]).toBe(`TOKEN=${tag}`)
})

test('a pack label is folded into the placeholder shape', async () => {
  expect((await scrub(memoryScan(named('123-customers')), [`TOKEN=${TOKEN}a`])).masked[0]).toMatch(/^TOKEN=\[CUSTOMERS-[0-9a-f]{8}\]$/)
  expect((await scrub(memoryScan(named('LITERAL')), [`TOKEN=${TOKEN}b`])).masked[0]).toMatch(/^TOKEN=\[LITERAL-LIST-[0-9a-f]{8}\]$/)
})

test('escaped text turns a live placeholder into a LITERAL one that restores to its own text', async () => {
  const tag = (await scrub(memoryScan(named()), [`TOKEN=${TOKEN}c`])).masked[0]!.slice('TOKEN='.length)
  const { masked } = await scrub(memoryScan(none), [`quoted ${tag}`], { escape: true })
  expect(masked[0]).toMatch(/^quoted \[LITERAL-[0-9a-f]{8}\]$/)
  expect(restore(masked[0]!)).toBe(`quoted ${tag}`)
})

test('a value hidden once is hidden again where no rule fires, unless it is short', async () => {
  const long = `${TOKEN}d`
  const tag = (await scrub(memoryScan(named()), [`TOKEN=${long} TOKEN=Drew`])).masked[0]!.match(TAG)![0]
  expect((await scrub(memoryScan(none), [`echo ${long} by Drew`])).masked[0]).toBe(`echo ${tag} by Drew`)
})

test('a handed value is hidden bare and in slices', async () => {
  const handed = 'Zq7' + 'xW9pLm2K'
  const { masked } = await scrub(memoryScan(none), [`got ${handed}, cut ${handed.slice(0, 7)}`], { handed: new Set([handed]) })
  expect(masked[0]).toMatch(/^got \[SECRET-[0-9a-f]{8}\], cut \[SECRET-[0-9a-f]{8}\]$/)
})

// The binary adapter, driven with a stand-in for `$.process.run` that answers
// as `redact scan --json` does: UTF-8 byte offsets into the joined stdin.
function binary(answer: (stdin: string) => unknown) {
  const runs: { argv: string[]; stdin: string }[] = []
  const $ = {
    process: {
      run: async (argv: string[], init: { stdin: string }) => {
        runs.push({ argv, stdin: init.stdin })
        return { exitCode: 0, stdout: JSON.stringify(answer(init.stdin)), stderr: '', isStdoutTruncated: false }
      },
    },
  }
  return { $, runs }
}
const bytes = (s: string) => new TextEncoder().encode(s).length
const at = (stdin: string, part: string, label = 'SECRET') => {
  const start = bytes(stdin.slice(0, stdin.indexOf(part)))
  return { start, end: start + bytes(part), label }
}

test('byte offsets land right after multi-byte characters', async () => {
  const text = `café 😀 naïve\nTOKEN=${TOKEN}\nafter`
  const { $ } = binary((stdin) => [at(stdin, TOKEN)])
  const [spans] = await binaryScan($, { binary: 'redact', timeoutMs: 1000 })([text])
  expect(spans!.map((s) => text.slice(s.start, s.end))).toEqual([TOKEN])
})

test('several texts go in one run, and a span across the join is cut to each side', async () => {
  const texts = ['first ends ab', 'cd second', `x TOKEN=${TOKEN}`]
  const { $, runs } = binary((stdin) => [{ start: bytes('first ends '), end: bytes(stdin.split('cd')[0]!) + 2, label: 'SECRET' }, at(stdin, TOKEN)])
  const spans = await binaryScan($, { binary: 'redact', timeoutMs: 1000 })(texts)
  expect(runs).toHaveLength(1)
  expect(spans.map((list, i) => list.map((s) => texts[i]!.slice(s.start, s.end)))).toEqual([['ab'], ['cd'], [TOKEN]])
})

test('overlapping spans merge under the first one\'s label', async () => {
  const text = `TOKEN=${TOKEN}`
  const { $ } = binary(() => [
    { start: 6, end: 12, label: 'B' },
    { start: 6, end: 10, label: 'A' },
    { start: 9, end: 18, label: 'C' },
  ])
  const { masked } = await scrub(binaryScan($, { binary: 'redact', timeoutMs: 1000 }), [text])
  expect(masked[0]).toMatch(new RegExp(`^TOKEN=\\[B-[0-9a-f]{8}\\]${TOKEN.slice(12)}$`))
})

test('output that is not JSON throws and says why', async () => {
  const why: string[] = []
  const $ = { process: { run: async () => ({ exitCode: 0, stdout: 'warning: old config', stderr: '', isStdoutTruncated: false }) } }
  await expect(binaryScan($, { binary: 'redact', timeoutMs: 1000, onBroken: (w) => why.push(w) })(['short'])).rejects.toThrow('unknown shape')
  expect(why).toHaveLength(1)
})

test('spans of an unknown shape throw and say why', async () => {
  const why: string[] = []
  for (const answer of [[{ byte_start: 0 }], { spans: [] }, [{ start: 0, end: 99, label: 'SECRET' }]]) {
    const { $ } = binary(() => answer)
    await expect(binaryScan($, { binary: 'redact', timeoutMs: 1000, onBroken: (w) => why.push(w) })(['short'])).rejects.toThrow('unknown shape')
  }
  expect(why).toHaveLength(3)
})

test('spans out of order or overlapping are merged before masking, so nothing leaks', async () => {
  const value = `${TOKEN}e`
  const text = `aaaaa TOKEN=${value} bbbbb`
  const at = text.indexOf(value)
  const scan: Scan = async () => [[
    { start: at + 4, end: at + value.length, label: 'B' },
    { start: at, end: at + 6, label: 'A' },
  ]]
  const { masked } = await scrub(scan, [text])
  expect(masked[0]).toMatch(/^aaaaa TOKEN=\[A-[0-9a-f]{8}\] bbbbb$/)
})

test('a scan that answers for fewer texts than it was given throws, so the hook withholds', async () => {
  const scan: Scan = async () => [[]]
  await expect(scrub(scan, ['one', `TOKEN=${TOKEN}`])).rejects.toThrow('2 texts')
})

// A session whose folder was removed while it ran (a merged worktree): a
// process cannot start in a folder that is gone, and the spawn fails with
// ENOENT as if the binary were missing. `dirs` are the folders that exist.
function goneFolder(dirs: string[], { binaries = ['redact'], fail }: { binaries?: string[]; fail?: Error } = {}) {
  const runs: { argv0: string; cwd?: string }[] = []
  const $ = {
    session: { cwd: async () => '/work/trees/gone' },
    env: { get: async () => undefined },
    fs: { exists: async (path: string) => dirs.includes(path) },
    process: {
      run: async (argv: string[], init: { stdin: string; cwd?: string }) => {
        runs.push({ argv0: argv[0]!, cwd: init.cwd })
        if (fail) throw fail
        if (!dirs.includes(init.cwd ?? '/work/trees/gone') || !binaries.includes(argv[0]!)) throw new Error(`failed to start: ENOENT: spawn ${argv[0]} ENOENT`)
        return { exitCode: 0, stdout: JSON.stringify([at(init.stdin, TOKEN)]), stderr: '', isStdoutTruncated: false }
      },
    },
  }
  return { $, runs }
}

test('a session folder that is gone scans from the nearest folder above it that exists', async () => {
  const { $, runs } = goneFolder(['/work', '/'])
  const why: string[] = []
  const { masked } = await scrub(binaryScan($, { binary: 'redact', timeoutMs: 1000, onBroken: (w) => why.push(w) }), [`TOKEN=${TOKEN}`])
  expect(masked[0]).toMatch(/^TOKEN=\[SECRET-[0-9a-f]{8}\]$/)
  expect(runs.at(-1)).toEqual({ argv0: 'redact', cwd: '/work' })
  expect(why).toEqual([])
})

test('a session folder with no folder above it still withholds, and names the folder', async () => {
  const { $ } = goneFolder([])
  const why: string[] = []
  await expect(binaryScan($, { binary: 'redact', timeoutMs: 1000, onBroken: (w) => why.push(w) })(['short'])).rejects.toThrow('/work/trees/gone')
  expect(why).toHaveLength(1)
})

test('a binary found nowhere throws, says it was not found and asks for the PATH hint', async () => {
  const { $ } = goneFolder(['/work/trees/gone'], { binaries: [] })
  const broken: [string, boolean][] = []
  const err = await binaryScan($, { binary: 'redact', timeoutMs: 1000, onBroken: (w, notFound) => broken.push([w, notFound]) })(['short']).catch((e) => e)
  expect(err).toBeInstanceOf(ScanFailed)
  expect(err.message).toContain('not found')
  expect(err.notFound).toBe(true)
  expect(broken).toEqual([[err.message, true]])
})

test('a scan that times out says so, and is not taken for a missing binary', async () => {
  const { $, runs } = goneFolder(['/work/trees/gone'], { fail: new Error('aborted: still running after 1000ms') })
  const err = await binaryScan($, { binary: 'redact', timeoutMs: 1000 })(['short']).catch((e) => e)
  expect(err).toBeInstanceOf(ScanFailed)
  expect(err.message).toContain('did not finish')
  expect(err.notFound).toBe(false)
  expect(runs).toHaveLength(1)
})

test('a binary that exits non-zero is not taken for a missing one', async () => {
  const $ = { process: { run: async () => ({ exitCode: 3, stdout: '', stderr: 'pack would not load', isStdoutTruncated: false }) } }
  const err = await binaryScan($, { binary: 'redact', timeoutMs: 1000 })(['short']).catch((e) => e)
  expect(err.message).toContain('exit 3: pack would not load')
  expect(err.notFound).toBe(false)
})
