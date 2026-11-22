import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { register } from '../hooks/redact.ts'

// Everyday tool output that holds no credential, run through the production
// hooks and scanner with the default packs: nothing in it may be withheld.
// Build with `cargo build` first. integration.test.mjs imports this file, so
// it runs first there, before any value is remembered; it also runs alone.
//
// Every name, path, host, org, project and email below is made up.

const binary = fileURLToPath(new URL(`../../target/debug/redact${process.platform === 'win32' ? '.exe' : ''}`, import.meta.url))
const dir = mkdtempSync(join(tmpdir(), 'redact-corpus-'))
const config = join(dir, 'config.toml')
writeFileSync(config, '')
after(() => rmSync(dir, { recursive: true }))

function hook(output) {
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
          env: { ...process.env, ...init.env, REDACT_CONFIG: config },
        })
        if (r.error) throw r.error
        return { exitCode: r.status, stdout: r.stdout, stderr: r.stderr, isStdoutTruncated: false }
      },
    },
    ui: { toast() {}, notice() {} },
  }
  return async (event) => {
    const next = Object.assign(async () => ({ result: output }), { budget: { remainingMs: 10000 } })
    try { return await handler(api, event, next) }
    catch { return rescue(api, event, next) }
  }
}

const bash = (command, stdout) => ({ event: { tool: 'Bash', command }, result: { stdout, stderr: '', interrupted: false, isImage: false } })

const markdown = `# Widget

A small cache for parsed documents.

## Develop

\`\`\`sh
mise install
cargo test
\`\`\`

The repository lives at https://dev.azure.com/fabrikam-labs/Gadgets/_git/widget-api and
mirrors to https://github.com/example-org/widget. Ask in #widget-dev, or mail
robin@example.com.

| Setting | Default |
| :- | :- |
| \`cache.ttl\` | 300 |
| \`cache.size\` | 64 MiB |
`

const CORPUS = [
  {
    name: 'git log',
    ...bash('git log -2', `commit 3f2a9c1e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a39
Author: Robin Sample <robin@example.com>
Date:   Mon Nov 16 09:12:44 2026 +0000

    fix(parser): keep the trailing newline in fenced blocks

    The fence parser dropped it when the block ended the file.

commit 9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d
Author: Alex Tester <alex.tester@example.org>
Date:   Sun Nov 15 18:03:10 2026 +0000

    docs: explain the --dry-run flag
`),
  },
  // One address per line: in the JSON view the line break before each one
  // reads `\n`, and the email rule takes that `n` into its match.
  { name: 'git log --format=%ae', ...bash('git log --format=%ae', 'robin.sample@fabrikamq.example\nalex.tester@fabrikamq.example\n') },
  {
    name: 'git status',
    ...bash('git status', `On branch feat/widget-cache
Your branch is up to date with 'origin/feat/widget-cache'.

Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
\tmodified:   src/cache/store.ts
\tmodified:   docs/guide/caching.md

Untracked files:
  (use "git add <file>..." to include in what will be committed)
\tnotes/2026-11-16.md

no changes added to commit (use "git add" and/or "git commit -a")
`),
  },
  // A tab before each SSH URL reads `\t` in the JSON view.
  {
    name: 'git remote -v',
    ...bash('git remote -v', 'origin\tgit@ssh.dev.azure.com:v3/fabrikam-labs/Gadgets/widget-api (fetch)\norigin\tgit@ssh.dev.azure.com:v3/fabrikam-labs/Gadgets/widget-api (push)\n'),
  },
  {
    name: 'gh pr view --json',
    ...bash('gh pr view 42 --json number,title,state,author,headRefName,baseRefName,url,body,files,reviewDecision', JSON.stringify({
      number: 42,
      title: 'feat(cache): evict entries by size',
      state: 'OPEN',
      author: { login: 'robin-sample', name: 'Robin Sample' },
      headRefName: 'feat/widget-cache',
      baseRefName: 'main',
      url: 'https://github.com/example-org/widget/pull/42',
      body: '## Summary\n\nEvicts by total size instead of entry count.\n\n- [x] tests\n- [ ] docs\n\nRefs #40',
      files: [
        { path: 'src/cache/store.ts', additions: 31, deletions: 6 },
        { path: 'docs/guide/caching.md', additions: 4, deletions: 1 },
      ],
      reviewDecision: 'REVIEW_REQUIRED',
    }, null, 2) + '\n'),
  },
  {
    name: 'env',
    ...bash('env', `HOME=/home/robin
USER=robin
LOGNAME=robin
SHELL=/bin/zsh
PATH=/home/robin/.local/bin:/home/robin/.local/share/mise/shims:/usr/local/bin:/usr/bin:/bin
TMPDIR=/tmp/robin-1000
LANG=en_US.UTF-8
EDITOR=nvim
TERM=xterm-256color
PWD=/home/robin/projects/widget
MISE_SHELL=zsh
GIT_PAGER=less -FRX
XDG_CONFIG_HOME=/home/robin/.config
`),
  },
  {
    name: 'mise ls',
    ...bash('mise ls', `Tool      Version  Source                                 Requested
lefthook  2.2.2    ~/projects/widget/mise.toml            2.2.2
node      24.11.0  ~/.config/mise/config.toml             24
python    3.13.9   ~/projects/widget/mise.toml            3.13
rust      1.99.1   ~/projects/widget/rust-toolchain.toml  1.99.1
`),
  },
  {
    name: 'rg',
    ...bash('rg -n "cache|evict"', `src/cache/store.ts:12:export const CACHE_TTL_SECONDS = 300
src/cache/store.ts:48:  // TODO: evict by size, not count
docs/guide/caching.md:7:Set \`cache.ttl\` in \`widget.toml\` to change how long entries live.
notes/2026-11-16.md:3:- ask Robin about the eviction policy
`),
  },
  { name: 'cat of a Markdown file', ...bash('cat README.md', markdown) },
  {
    name: 'Read of a Markdown file',
    event: { tool: 'Read', file_path: '/home/robin/projects/widget/README.md' },
    result: { type: 'text', file: { filePath: '/home/robin/projects/widget/README.md', content: markdown, numLines: 21, startLine: 1, totalLines: 21 } },
  },
  {
    name: 'az account show',
    ...bash('az account show -o json', JSON.stringify({
      environmentName: 'AzureCloud',
      homeTenantId: '3c1f9a2e-7b4d-4e8a-9c6f-2d5e8b1a7f04',
      id: '8d2b6e1f-4a9c-4f3e-b7d1-6c0a9e5f2b18',
      isDefault: true,
      managedByTenants: [],
      name: 'Fabrikam Development',
      state: 'Enabled',
      tenantId: '3c1f9a2e-7b4d-4e8a-9c6f-2d5e8b1a7f04',
      user: { name: 'robin@example.com', type: 'user' },
    }, null, 2) + '\n'),
  },
  {
    name: 'az repos show',
    ...bash('az repos show -r widget-api -o json', JSON.stringify({
      defaultBranch: 'refs/heads/main',
      id: 'f4e3d2c1-b0a9-4876-9543-210fedcba987',
      isDisabled: false,
      name: 'widget-api',
      project: { id: '0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d', name: 'Gadgets', state: 'wellFormed', visibility: 'private' },
      remoteUrl: 'https://fabrikam-labs@dev.azure.com/fabrikam-labs/Gadgets/_git/widget-api',
      size: 482113,
      sshUrl: 'git@ssh.dev.azure.com:v3/fabrikam-labs/Gadgets/widget-api',
      webUrl: 'https://dev.azure.com/fabrikam-labs/Gadgets/_git/widget-api',
    }, null, 2) + '\n'),
  },
  {
    name: 'az ad user list -o tsv',
    ...bash('az ad user list --query "[].[mail,displayName]" -o tsv', 'robin.sample@fabrikamq.example\tRobin Sample\nalex.tester@fabrikamq.example\tAlex Tester\n'),
  },
]

// Known gaps: the corpus holds no credential, so ideally nothing in it turns
// into a placeholder. These cases still do, from the rules themselves (issue
// #115, cause 3; PR #118 and its follow-ups), not from how a result is mapped.
// Each entry is the sorted placeholder labels the case shows, one per
// placeholder. A change to the rules changes them, and this test then fails:
// shrink the list to match.
const KNOWN_GAPS = {
  // identity:git-person hides each Author name.
  'git log': ['PERSON', 'PERSON'],
  // identity:email hides an address outside the reserved example domains.
  'git log --format=%ae': ['EMAIL', 'EMAIL'],
  // The azure work-name rules hide the org and project in each SSH URL.
  'git remote -v': ['ORG', 'ORG', 'PROJECT', 'PROJECT'],
  // The author's display name, beside the login, hides as a person.
  'gh pr view --json': ['PERSON'],
  // PWD holds `PW`, so env-dump reads it as a password (#115, comment).
  env: ['SECRET'],
  // gcp:project-path hides the folder under ~/projects (#109).
  'mise ls': ['PROJECT', 'PROJECT', 'PROJECT'],
  // The azure work-name rules hide the org, project and repo in the URL.
  'cat of a Markdown file': ['ORG', 'PROJECT', 'REPO'],
  // As above, plus gcp:project-path on the file's path under ~/projects (#109).
  'Read of a Markdown file': ['ORG', 'PROJECT', 'PROJECT', 'PROJECT', 'PROJECT', 'PROJECT', 'REPO'],
  // The tenant and subscription IDs, the subscription's name and the user.
  'az account show': ['ID', 'ID', 'ID', 'RESOURCE', 'USER'],
  // The azure work-name rules hide the org, project and repo in each URL and field.
  'az repos show': ['ORG', 'ORG', 'ORG', 'ORG', 'PROJECT', 'PROJECT', 'PROJECT', 'PROJECT', 'REPO', 'REPO', 'REPO', 'REPO'],
  // identity:email hides each address. Both names were hidden in git log
  // earlier in this session, so they are hidden again on sight (#115, cause 3).
  'az ad user list -o tsv': ['EMAIL', 'EMAIL', 'PERSON', 'PERSON'],
}

const labels = (r) => (JSON.stringify(r.result).match(/\[[A-Z][A-Z0-9-]*-[0-9a-f]{8}\]/g) ?? []).map((t) => t.slice(1, -10)).sort()

for (const c of CORPUS) {
  test(`corpus: ${c.name} is not withheld`, async () => {
    const r = await hook(c.result)(c.event)
    assert.equal(r.deny, undefined, `${c.name}: ${r.deny}`)
    assert.deepEqual(labels(r), KNOWN_GAPS[c.name] ?? [], `${c.name}: placeholders changed; update KNOWN_GAPS`)
  })
}

// Safety: a credential in the same everyday output is still hidden, or the
// result is withheld. Built at run time so no token-shaped value sits in the repo.
const token = 'ghp_' + 'Q7mK2xV9pL4sT8nW3cR6' + 'yB1dF5hJ0aE2gZ4uN6'
for (const [name, stdout] of [
  ['an env line', `HOME=/home/robin\nGITHUB_TOKEN=${token}\nSHELL=/bin/zsh\n`],
  ['a bare line', `robin.sample@fabrikamq.example\n${token}\nalex.tester@fabrikamq.example\n`],
  ['a JSON document', JSON.stringify({ user: { name: 'robin@example.com' }, accessToken: token }, null, 2)],
]) {
  test(`corpus: a credential on ${name} is hidden or withheld`, async () => {
    const r = await hook({ stdout, stderr: '', interrupted: false, isImage: false })({ tool: 'Bash', command: 'cat notes.txt' })
    if (r.deny === undefined) assert.ok(!JSON.stringify(r).includes(token), JSON.stringify(r))
  })
}
