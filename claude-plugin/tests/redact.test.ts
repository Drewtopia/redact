import { expect, test } from 'claude-code/testing'

// A stand-in for the redact binary: it hides the value after TOKEN= or
// PASSWORD= and reports UTF-8 byte offsets, as `redact scan --json` does.
// Fake values are built at run time so no key-shaped string sits in the repo.
const TOKEN = 'abc123' + 'def456ghi789'
const TAG = /\[SECRET-[0-9a-f]{8}\]/

type Answer = { deny?: string; result?: unknown; text?: string; isError?: boolean }
const call = async ($: any, input: Record<string, unknown>): Promise<Answer> => (await $.tool.call(input as never)) as Answer

// Claude Code beneath the mod: each tool prints `output(e)`; `seen` keeps what it was given.
function fakeRedact(on: any) {
  on('process.run', (_$: unknown, e: any) => {
    const text: string = e.init?.stdin ?? ''
    const bytes = (s: string) => new TextEncoder().encode(s).length
    const spans = [...text.matchAll(/(?:TOKEN|PASSWORD)=(\S+)/g)].map((m) => {
      const value = m[1] ?? ""
      const start = bytes(text.slice(0, (m.index ?? 0) + m[0].length - value.length))
      return { start, end: start + bytes(value), label: 'SECRET', pack: 'credentials', rule: 'named-secret' }
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

test('spans of an unknown shape withhold the result', async ($, on) => {
  on('ui.notice', () => ({ value: undefined }))
  on('ui.toast', () => ({ value: undefined }))
  on('process.run', () => ({ value: { exitCode: 0, stdout: '[{"byte_start":0}]', stderr: '', isStdoutTruncated: false, isStderrTruncated: false } }))
  on('tool.call', () => ({ result: `TOKEN=${TOKEN}` }))
  const r = await call($, { tool: 'Bash', command: 'cat .env' })
  expect(JSON.stringify(r)).not.toContain(TOKEN)
  expect(JSON.stringify(r)).toContain('withheld')
})
