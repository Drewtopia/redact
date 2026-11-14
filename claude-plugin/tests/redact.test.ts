import { expect, test } from 'claude-code/testing'

// A stand-in for the redact binary: it hides the value after TOKEN= or
// PASSWORD= and reports UTF-8 byte offsets, as `redact scan --json` does.
// Fake values are built at run time so no key-shaped string sits in the repo.
const TOKEN = 'abc123' + 'def456ghi789'
const TAG = /\[SECRET-[0-9a-f]{8}\]/

type Answer = { deny?: string; result?: unknown; text?: string; isError?: boolean }
const call = async ($: any, input: Record<string, unknown>): Promise<Answer> => (await $.tool.call(input as never)) as Answer

// Claude Code beneath the mod: each tool prints `output(e)`; `seen` keeps what it was given.
function fakeRedact(on: any, label = 'SECRET') {
  on('process.run', (_$: unknown, e: any) => {
    const text: string = e.init?.stdin ?? ''
    const bytes = (s: string) => new TextEncoder().encode(s).length
    // `password: x` stands for a rule keyed on a field name.
    const spans = [...text.matchAll(/(?:TOKEN|PASSWORD)=(\S+)|^password: (\S+)$/gm)].map((m) => {
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

  await call($, { tool: 'Bash', command: `curl -H x:${tag} example.test` })
  expect(seen[1].command).toBe(`curl -H x:${TOKEN} example.test`)

  // A commit message keeps the placeholder: it would leave the machine.
  await call($, { tool: 'Bash', command: `git commit -m "rotate ${tag}"` })
  expect(seen[2].command).toContain(tag)
})

test('PowerShell gets real values, but not into git and not with PowerShell syntax in them', async ($, on) => {
  const seen = tools(on, (e) => (e.command === 'cat .env' ? `TOKEN=${TOKEN}\nTOKEN=me@example.test\n` : 'ok'))
  const [tag, at] = String((await call($, { tool: 'PowerShell', command: 'cat .env' })).result).match(new RegExp(TAG, 'g')) ?? []

  await call($, { tool: 'PowerShell', command: `Invoke-RestMethod -Headers @{x='${tag}'} example.test` })
  expect(seen[1].command).toContain(TOKEN)
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

test('byte offsets land right after multi-byte characters', async ($, on) => {
  tools(on, () => `café 😀 naïve\nTOKEN=${TOKEN}\nafter`)
  const out = String((await call($, { tool: 'Bash', command: 'cat notes' })).result)
  expect(out).toMatch(/^café 😀 naïve\nTOKEN=\[SECRET-[0-9a-f]{8}\]\nafter$/)
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

test('a word list label that starts with a digit still masks', async ($, on) => {
  fakeRedact(on, '123-CUSTOMERS')
  on('tool.call', () => ({ result: `TOKEN=${TOKEN}` }))
  const out = String((await call($, { tool: 'Bash', command: 'cat .env' })).result)
  expect(out).toMatch(/^TOKEN=\[CUSTOMERS-[0-9a-f]{8}\]$/)
})

test("a subagent's answer that holds a live placeholder passes through", async ($, on) => {
  fakeRedact(on)
  on('tool.call', (_$: unknown, e: any) => ({ result: e.tool === 'Bash' ? `TOKEN=${TOKEN}\n` : { status: 'done', content: `saved ${e.tag} ok`, log: "PASSWORD=unrelated-value-99" } }))
  const tag = String((await call($, { tool: 'Bash', command: 'cat .env' })).result).match(TAG)?.[0]
  const r = await call($, { tool: 'Agent', prompt: 'save it', tag })
  expect(r.deny).toBeUndefined()
  expect((r.result as any).content).toBe(`saved ${tag} ok`)
})
