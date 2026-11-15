import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { register } from '../hooks/redact.ts'

// Build with `cargo build` first. These tests use the production hooks and
// scanner together; only the tool beneath the redactor is a stand-in.
const binary = fileURLToPath(new URL(`../../target/debug/redact${process.platform === 'win32' ? '.exe' : ''}`, import.meta.url))
const dir = mkdtempSync(join(tmpdir(), 'redact-integration-'))
const config = join(dir, 'config.toml')
writeFileSync(config, '')
after(() => rmSync(dir, { recursive: true }))

function scan(text, args = []) {
  const r = spawnSync(binary, [...args, 'scan', '--json'], {
    input: text,
    encoding: 'utf8',
    timeout: 3000,
    env: { ...process.env, REDACT_CONFIG: config },
  })
  assert.equal(r.error, undefined, r.error?.message)
  assert.equal(r.status, 0, r.stderr)
  return JSON.parse(r.stdout)
}

function hook(output, configPath = config) {
  let handler, rescue
  register((name, fn) => {
    if (name === 'tool.call') handler = fn
    return { catch(fn) { if (name === 'tool.call') rescue = fn } }
  }, { binary, notify: false })
  const api = {
    process: {
      async run(argv, init) {
        const r = spawnSync(argv[0], argv.slice(1), {
          input: init.stdin,
          encoding: 'utf8',
          timeout: init.timeoutMs,
          env: { ...process.env, ...init.env, REDACT_CONFIG: configPath },
        })
        if (r.error) throw r.error
        return { exitCode: r.status, stdout: r.stdout, stderr: r.stderr, isStdoutTruncated: false }
      },
    },
    ui: { toast() {}, notice() {} },
  }
  const seen = []
  return {
    seen,
    async call(event) {
      const next = Object.assign(async (input) => {
        seen.push(input)
        return { result: output(input) }
      }, { budget: { remainingMs: 10000 } })
      try { return await handler(api, event, next) }
      catch { return rescue(api, event, next) }
    },
  }
}

for (const [name, result, secret] of [
  ['Kubernetes Secret', { kind: 'Secret', data: { key: 'c2VjcmV0' }, metadata: { name: 'sample' } }, 'c2VjcmV0'],
  ['Docker registry auth', { auths: { registry: { auth: 'dXNlcjpwYXNz' } } }, 'dXNlcjpwYXNz'],
  ['long password', { password: 'correcthorse'.repeat(100), user: 'ann' }, 'correcthorse'.repeat(100)],
  ['multiline password', { password: 'firstline\nsecondline', user: 'ann' }, 'firstline\nsecondline'],
  ['JSON escapes in a password', { password: 'café\\folder\t"quoted"\n😀', user: 'ann' }, 'café\\folder\t"quoted"\n😀'],
]) {
  test(`a structured ${name} is hidden and restores to its original value`, async () => {
    const h = hook((e) => e.tool === 'Read' ? result : 'written')
    const r = await h.call({ tool: 'Read', file_path: 'synthetic.json' })
    assert.equal(r.deny, undefined)
    assert.ok(!JSON.stringify(r).includes(JSON.stringify(secret).slice(1, -1)))
    const tag = JSON.stringify(r.result).match(/\[[A-Z][A-Z0-9-]*-[0-9a-f]{8}\]/)?.[0]
    assert.ok(tag, JSON.stringify(r))
    await h.call({ tool: 'Write', file_path: 'synthetic.txt', content: tag })
    assert.equal(h.seen.at(-1).content, secret)
    if ('user' in result) assert.equal(r.result.user, 'ann')
    const again = await h.call({ tool: 'Read', file_path: 'synthetic.json' })
    assert.equal(again.deny, undefined)
    assert.ok(!JSON.stringify(again).includes(JSON.stringify(secret).slice(1, -1)))
  })
}

test('a match crossing JSON fields withholds the result instead of guessing', async () => {
  const path = join(dir, 'cross-config.toml')
  writeFileSync(path, 'import = ["cross.toml"]\n')
  writeFileSync(join(dir, 'cross.toml'), String.raw`schema_version = 1
id = "cross"
[[rules]]
id = "pair"
regex = '"left"\s*:\s*"[^"]+"\s*,\s*"right"'
label = "SECRET"
`)
  const h = hook(() => ({ left: 'hello', right: 'world' }), path)
  const r = await h.call({ tool: 'Read', file_path: 'synthetic.json' })
  assert.ok(r.deny?.includes('withheld'), JSON.stringify(r))
})

test('Git global options cannot restore a credential into a commit message', async () => {
  const secret = 'synthetic-password-987654'
  const h = hook((e) => e.tool === 'Read' ? { password: secret } : 'ok')
  const tag = (await h.call({ tool: 'Read', file_path: 'synthetic.json' })).result.password
  for (const command of [
    `git --work-tree . commit -m "${tag}"`,
    `git --git-dir "repo path/.git" commit -m "${tag}"`,
    `git --git-dir="repo path/.git" commit -m "${tag}"`,
    `git -C my" repo" commit -m "${tag}"`,
    `git -C"my repo" commit -m "${tag}"`,
    `git --work-tree my\\ repo commit -m "${tag}"`,
    `git --namespace demo tag -m "${tag}" release`,
    `git --config-env=alias.save=GIT_SAVE commit -m "${tag}"`,
    `GIT --WORK-TREE . COMMIT -m "${tag}"`,
    `gh --repo owner/repo pr create --body "${tag}"`,
  ]) {
    await h.call({ tool: 'Bash', command })
    assert.equal(h.seen.at(-1).command, command)
  }
  for (const path of ['my` repo', '"my`" repo"']) {
    const command = `git --work-tree ${path} commit -m "${tag}"`
    await h.call({ tool: 'PowerShell', command })
    assert.equal(h.seen.at(-1).command, command)
  }
  await h.call({ tool: 'Bash', command: `curl -H x:${tag} example.test` })
  assert.equal(h.seen.at(-1).command, `curl -H x:${secret} example.test`)
})

test('an excluded whole match makes progress, including at a Unicode boundary', () => {
  const path = join(dir, 'except.toml')
  writeFileSync(path, `schema_version = 1
id = "probe"
[[rules]]
id = "skip"
regex = "é|secret"
exceptMatch = "é|secret"
[[rules]]
id = "hide"
regex = "hidden"
label = "SECRET"
`)
  const spans = scan('é secret hidden', ['--only-files', '--file', path])
  assert.equal(spans.length, 1)
  assert.equal(spans[0].start, Buffer.byteLength('é secret '))
})

test('sensitive pack IDs are absent from JSON and explain output', () => {
  const path = join(dir, 'metadata.toml')
  writeFileSync(path, `schema_version = 1
id = "Fabrikam"
[[rules]]
id = "r"
regex = "Fabrikam"
label = "ORG"
`)
  const r = spawnSync(binary, ['--only-files', '--file', path, 'scan', '--json', '--explain'], {
    input: 'Fabrikam', encoding: 'utf8', timeout: 3000,
  })
  assert.equal(r.status, 0, r.stderr)
  assert.ok(!`${r.stdout}${r.stderr}`.toLowerCase().includes('fabrikam'))
  assert.equal(JSON.parse(r.stdout)[0].pack, 'VALUE')
})
