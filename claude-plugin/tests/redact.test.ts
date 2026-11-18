import { expect, mock, test } from 'claude-code/testing'
import { MOD_VERSION } from '../hooks/redact.ts'

// A stand-in for the redact binary: it hides the value after TOKEN= or
// PASSWORD= and reports UTF-8 byte offsets, as `redact scan --json` does.
// Fake values are built at run time so no key-shaped string sits in the repo.
const TOKEN = 'abc123' + 'def456ghi789'
const TAG = /\[SECRET-[0-9a-f]{8}\]/

type Answer = { deny?: string; result?: unknown; text?: string; isError?: boolean }
const call = async ($: any, input: Record<string, unknown>): Promise<Answer> => (await $.tool.call(input as never)) as Answer

// Claude Code beneath the mod: each tool prints `output(e)`; `seen` keeps what it was given.
// `start` runs first and may throw, as a spawn that cannot find the binary does.
function fakeRedact(on: any, label = 'SECRET', start?: (argv0: string) => void) {
  on('process.run', (_$: unknown, e: any) => {
    start?.(e.argv[0])
    const text: string = e.init?.stdin ?? ''
    const bytes = (s: string) => new TextEncoder().encode(s).length
    // `password: x` stands for a rule keyed on a field name.
    // A JSON string's closing quote is not part of the value, just as in
    // the real scanner. Results are scanned as JSON as well as plain leaves.
    const spans = [...text.matchAll(/(?:TOKEN|PASSWORD)=([^\s"]+)|^password: (\S+)$/gm)].map((m) => {
      const value = m[1] ?? m[2] ?? ""
      const start = bytes(text.slice(0, (m.index ?? 0) + m[0].length - value.length))
      return { start, end: start + bytes(value), label, pack: 'credentials', rule: 'named-secret' }
    })
    return { value: { exitCode: 0, stdout: JSON.stringify(spans), stderr: '', isStdoutTruncated: false, isStderrTruncated: false } }
  })
  on('ui.notice', () => ({ value: undefined }))
  on('ui.toast', () => ({ value: undefined }))
}

function tools(on: any, output: (e: any) => string, seen: any[] = []) {
  fakeRedact(on)
  on('tool.call', (_$: unknown, e: any) => {
    seen.push(e)
    return { result: output(e) }
  })
  return seen
}

test('a secret in Bash output comes back as a placeholder, and goes back in for the next command', async ($, on) => {
  const seen = tools(on, (e) => (e.command === 'cat .env' ? `TOKEN=${TOKEN}\n` : 'ok'))
  const out = String((await call($, { tool: 'Bash', command: 'cat .env' })).result)
  expect(out).not.toContain(TOKEN)
  const tag = out.match(TAG)?.[0]
  expect(tag).toBeDefined()

  await call($, { tool: 'Bash', command: `./deploy.sh -H x:${tag}` })
  expect(seen[1].command).toBe(`./deploy.sh -H x:${TOKEN}`)

  // A commit message keeps the placeholder: it would leave the machine.
  await call($, { tool: 'Bash', command: `git commit -m "rotate ${tag}"` })
  expect(seen[2].command).toContain(tag)
})

test('PowerShell gets real values, but not into git and not with PowerShell syntax in them', async ($, on) => {
  const seen = tools(on, (e) => (e.command === 'cat .env' ? `TOKEN=${TOKEN}\nTOKEN=me@example.test\n` : 'ok'))
  const [tag, at] = String((await call($, { tool: 'PowerShell', command: 'cat .env' })).result).match(new RegExp(TAG, 'g')) ?? []

  await call($, { tool: 'PowerShell', command: `./deploy.ps1 -Key ${tag}` })
  expect(seen[1].command).toContain(TOKEN)
  // restoreHosts is empty by default: no real value goes to the network.
  expect((await call($, { tool: 'PowerShell', command: `Invoke-RestMethod -Headers @{x='${tag}'} https://example.test` })).deny ?? '').toContain('restoreHosts')
  expect(seen.length).toBe(2)
  await call($, { tool: 'PowerShell', command: `git commit -m "rotate ${tag}"` })
  expect(seen[2].command).toContain(tag)

  // @ splats in PowerShell, so a value holding one stays out; Bash takes it.
  expect((await call($, { tool: 'PowerShell', command: `echo ${at}` })).deny ?? '').toContain('shell characters')
  await call($, { tool: 'Bash', command: `echo ${at}` })
  expect(seen.at(-1).command).toBe('echo me@example.test')
})

test('a value the tool was handed is hidden when printed back bare', async ($, on) => {
  tools(on, (e) => (e.command === 'cat .env' ? `TOKEN=${TOKEN}\n` : `echoed ${TOKEN}`))
  const tag = String((await call($, { tool: 'Bash', command: 'cat .env' })).result).match(TAG)?.[0]
  const out = String((await call($, { tool: 'Bash', command: `printf %s ${tag}` })).result)
  expect(out).toBe(`echoed ${tag}`)
})

test('several strings in one result are each masked', async ($, on) => {
  fakeRedact(on)
  on('tool.call', () => ({ result: { a: `TOKEN=${TOKEN}`, b: ['plain', `PASSWORD=${TOKEN}x`] } }))
  const r = (await call($, { tool: 'Read', file_path: 'x.json' })).result as any
  expect(r.a).toMatch(/^TOKEN=\[SECRET-[0-9a-f]{8}\]$/)
  expect(r.b[0]).toBe('plain')
  expect(r.b[1]).toMatch(/^PASSWORD=\[SECRET-[0-9a-f]{8}\]$/)
})

test('a binary that fails withholds the result instead of passing it raw', async ($, on) => {
  on('ui.notice', () => ({ value: undefined }))
  on('ui.toast', () => ({ value: undefined }))
  on('process.run', () => ({ value: { exitCode: 3, stdout: '', stderr: 'pack would not load', isStdoutTruncated: false, isStderrTruncated: false } }))
  on('tool.call', () => ({ result: `TOKEN=${TOKEN}` }))
  const r = await call($, { tool: 'Bash', command: 'cat .env' })
  expect(JSON.stringify(r)).not.toContain(TOKEN)
  expect(JSON.stringify(r)).toContain('withheld')
})

test('an errored result is withheld as a refusal when the scan fails', async ($, on) => {
  on('ui.notice', () => ({ value: undefined }))
  on('ui.toast', () => ({ value: undefined }))
  on('process.run', () => ({ value: { exitCode: 3, stdout: '', stderr: 'pack would not load', isStdoutTruncated: false, isStderrTruncated: false } }))
  on('tool.call', () => ({ isError: true, result: { stdout: `TOKEN=${TOKEN}`, stderr: '', interrupted: false, isImage: false } }))
  const r = await call($, { tool: 'Bash', command: 'cat .env' })
  expect(r.deny).toContain('withheld')
  expect(JSON.stringify(r)).not.toContain(TOKEN)
})

// Core reports a failed Bash command with its error text as `result`, a string
// where the tool's output object goes. Handing that back as a result breaks
// the tool's output shape, so the masked error comes back as a refusal.
test('a failed command whose error holds a secret comes back masked', async ($, on) => {
  fakeRedact(on)
  const error = `Exit code 1\nTOKEN=${TOKEN}\ncat: sample.txt: No such file or directory`
  on('tool.call', () => ({ isError: true, result: error, text: error }))
  const r = await call($, { tool: 'Bash', command: 'cat .env sample.txt' })
  expect(JSON.stringify(r)).not.toContain(TOKEN)
  expect(r.deny).toMatch(TAG)
  expect(r.deny).toContain('No such file or directory')
})

test('a result nested too deep to scan is withheld, even with nothing else hidden', async ($, on) => {
  let deep: unknown = `TOKEN=${TOKEN}`
  for (let i = 0; i < 70; i++) deep = { deep }
  fakeRedact(on)
  on('tool.call', () => ({ result: deep }))
  const r = await call($, { tool: 'mcp__x__get', id: 1 })
  expect(JSON.stringify(r)).not.toContain(TOKEN)
  expect(JSON.stringify(r)).toContain('withheld')
})

test('spans of an unknown shape withhold the result', async ($, on) => {
  on('ui.notice', () => ({ value: undefined }))
  on('ui.toast', () => ({ value: undefined }))
  on('process.run', () => ({ value: { exitCode: 0, stdout: '[{"byte_start":0}]', stderr: '', isStdoutTruncated: false, isStderrTruncated: false } }))
  on('tool.call', () => ({ result: `TOKEN=${TOKEN}` }))
  const r = await call($, { tool: 'Bash', command: 'cat .env' })
  expect(JSON.stringify(r)).not.toContain(TOKEN)
  expect(JSON.stringify(r)).toContain('withheld')
})

test('a secret held in an object key is masked in the key', async ($, on) => {
  fakeRedact(on)
  on('tool.call', () => ({ result: { [`TOKEN=${TOKEN}`]: true } }))
  const r = (await call($, { tool: 'mcp__x__get', id: 1 })).result as any
  expect(JSON.stringify(r)).not.toContain(TOKEN)
  expect(Object.keys(r)[0]).toMatch(/^TOKEN=\[SECRET-[0-9a-f]{8}\]$/)
})

test('a value known as a secret only by its field name is masked', async ($, on) => {
  const pw = 'hunter' + '2-correct-horse'
  fakeRedact(on)
  on('tool.call', () => ({ result: { user: 'ann', password: pw, note: `set to ${pw}` } }))
  const r = (await call($, { tool: 'mcp__x__get', id: 1 })).result as any
  expect(JSON.stringify(r)).not.toContain(pw)
  expect(r.password).toMatch(TAG)
  expect(r.note).toBe(`set to ${r.password}`)
  expect(r.user).toBe('ann')
})

test('a secret stored as a number withholds the result', async ($, on) => {
  fakeRedact(on)
  on('tool.call', () => ({ result: { password: 12345678 } }))
  const r = await call($, { tool: 'mcp__x__get', id: 1 })
  expect(r.deny).toContain('number')
  expect(JSON.stringify(r)).not.toContain('12345678')
})

test('a LITERAL label from the binary still gets the shell check', async ($, on) => {
  fakeRedact(on, 'LITERAL')
  const seen: any[] = []
  on('tool.call', (_$: unknown, e: any) => (seen.push(e), { result: e.command === 'cat words' ? 'TOKEN=review;echo-injected' : 'ok' }))
  const tag = String((await call($, { tool: 'Bash', command: 'cat words' })).result).match(/\[[A-Z-]+-[0-9a-f]{8}\]/)?.[0]
  expect(tag).toBeDefined()
  expect(tag).not.toMatch(/^\[LITERAL-[0-9a-f]{8}\]$/)
  expect((await call($, { tool: 'Bash', command: `echo ${tag}` })).deny ?? '').toContain('shell characters')
  expect(seen).toHaveLength(1)
})

test('git with a quoted -C path, and Azure DevOps, keep their placeholders', async ($, on) => {
  const seen = tools(on, (e) => (e.command === 'cat .env' ? `TOKEN=${TOKEN}\n` : 'ok'))
  const tag = String((await call($, { tool: 'Bash', command: 'cat .env' })).result).match(TAG)?.[0]
  await call($, { tool: 'Bash', command: `git -C "my repo" commit -m "rotate ${tag}"` })
  await call($, { tool: 'Bash', command: `az repos pr create --description "${tag}"` })
  expect(seen[1].command).toContain(tag)
  expect(seen[2].command).toContain(tag)
})

test('an @-mentioned UTF-16 file is scanned, not passed as binary', async ($, on) => {
  fakeRedact(on)
  const utf16 = [...`TOKEN=${TOKEN}\r\n`].join('\u0000') + '\u0000'
  on('fs.read', () => ({ value: utf16 }))
  on('fs.exists', () => ({ value: true }))
  on('prompt.mention', () => ({ type: null }))
  const r = (await $.prompt.mention({ mention: '@setup.ps1', path: 'setup.ps1' })) as { deny?: string }
  expect(r.deny ?? '').toContain('holds something to hide')
})

test("a subagent's answer that holds a live placeholder passes through", async ($, on) => {
  fakeRedact(on)
  on('tool.call', (_$: unknown, e: any) => ({ result: e.tool === 'Bash' ? `TOKEN=${TOKEN}\n` : { status: 'done', content: `saved ${e.tag} ok`, log: "PASSWORD=unrelated-value-99" } }))
  const tag = String((await call($, { tool: 'Bash', command: 'cat .env' })).result).match(TAG)?.[0]
  const r = await call($, { tool: 'Agent', prompt: 'save it', tag })
  expect(r.deny).toBeUndefined()
  expect((r.result as any).content).toBe(`saved ${tag} ok`)
})

// A session started before redact was installed: `redact` is not on its PATH,
// but an installer put it in one of the folders locate tries.
function missingFromPath(on: any, installed: string[], argv0s: string[] = []) {
  mock.env(on, { HOME: '/home/t' })
  on('fs.exists', (_$: unknown, e: any) => ({ value: installed.includes(e.path) }))
  fakeRedact(on, 'SECRET', (argv0) => {
    argv0s.push(argv0)
    if (!installed.includes(argv0)) throw new Error(`spawn ${argv0} ENOENT`)
  })
  return argv0s
}

test('redact missing from PATH is found in the mise shims folder, and that path is kept', async ($, on) => {
  const shim = '/home/t/.local/share/mise/shims/redact'
  const argv0s = missingFromPath(on, [shim])
  on('tool.call', () => ({ result: `TOKEN=${TOKEN}` }))
  const first = String((await call($, { tool: 'Bash', command: 'cat .env' })).result)
  const second = String((await call($, { tool: 'Bash', command: 'cat .env' })).result)
  expect(first).toMatch(/^TOKEN=\[SECRET-[0-9a-f]{8}\]$/)
  expect(second).toMatch(/^TOKEN=\[SECRET-[0-9a-f]{8}\]$/)
  // The scan, the once-a-session version check, then the next scan: all through the kept path.
  expect(argv0s).toEqual(['redact', shim, shim, shim])
})

test('redact found nowhere still withholds the result', async ($, on) => {
  missingFromPath(on, [])
  on('tool.call', () => ({ result: `TOKEN=${TOKEN}` }))
  const r = await call($, { tool: 'Bash', command: 'cat .env' })
  expect(JSON.stringify(r)).not.toContain(TOKEN)
  expect(JSON.stringify(r)).toContain('withheld')
})

test('a binary from another release than the mod gets one toast that says so', async ($, on) => {
  const toasts: string[] = []
  on('ui.notice', () => ({ value: undefined }))
  on('ui.toast', (_$: unknown, e: unknown) => (toasts.push(JSON.stringify(e)), { value: undefined }))
  on('process.run', (_$: unknown, e: any) => ({
    value: { exitCode: 0, stdout: e.argv[1] === '--version' ? 'redact 0.0.1\n' : '[]', stderr: '', isStdoutTruncated: false, isStderrTruncated: false },
  }))
  on('tool.call', () => ({ result: 'ok' }))
  await call($, { tool: 'Bash', command: 'ls' })
  await call($, { tool: 'Bash', command: 'ls' })
  expect(toasts.length).toBe(1)
  expect(toasts[0]).toContain('0.0.1')
  expect(toasts[0]).toContain(MOD_VERSION)
})

test('a binary from the same release gets no toast', async ($, on) => {
  const toasts: string[] = []
  on('ui.notice', () => ({ value: undefined }))
  on('ui.toast', (_$: unknown, e: unknown) => (toasts.push(JSON.stringify(e)), { value: undefined }))
  on('process.run', (_$: unknown, e: any) => ({
    value: { exitCode: 0, stdout: e.argv[1] === '--version' ? `redact ${MOD_VERSION}\n` : '[]', stderr: '', isStdoutTruncated: false, isStderrTruncated: false },
  }))
  on('tool.call', () => ({ result: 'ok' }))
  await call($, { tool: 'Bash', command: 'ls' })
  expect(toasts).toEqual([])
})
