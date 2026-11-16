# Context

## Open issues

!`gh issue list --state open --label ready-for-agent --limit 100 --json number,title,body,labels,comments --jq '[.[] | {number, title, body, labels: [.labels[].name], comments: [.comments[].body]}]'`

The list above has already been filtered to issues ready for work and is the sole source of truth for what work exists. Do not run your own unfiltered query to find more issues — if the list is empty, there is nothing to do.

## Recent agent commits (last 10)

!`git log --oneline --grep="Co-Authored-By: Claude" -10`

# Task

You are an autonomous coding agent working through issues one at a time.

## Priority order

Work on issues in this order:

1. **Bug fixes** — broken behaviour affecting users
2. **Tracer bullets** — thin end-to-end slices that prove an approach works
3. **Polish** — improving existing functionality (error messages, UX, docs)
4. **Refactors** — internal cleanups with no user-visible change

Pick the highest-priority open issue that is not blocked by another open issue.

## Workflow

1. **Explore** — read the issue carefully. Pull in the parent PRD if referenced. Read the repo's agent guide, `CONTRIBUTING.md`, and the relevant source files and tests before writing any code.
2. **Plan** — decide what to change and why. Keep the change as small as possible.
3. **Execute** — use RGR (Red → Green → Repeat → Refactor): write a failing test first, then write the implementation to pass it.
4. **Verify** — run what CI runs, and fix any failure before committing:
   - `cargo fmt --check`
   - `cargo clippy --all-targets -- -D warnings`
   - `cargo test`
5. **Commit** — make a single git commit with a Conventional Commits message (`fix: …`, `feat: …`, `refactor: …`; see `commit-check.toml`). The body says what changed and why, lists key decisions, and ends with `Closes #<ID>`. Keep the `Co-Authored-By` trailer.

## Rules

- Work on **one issue per iteration**. Do not attempt multiple issues in a single iteration.
- Never close an issue, push, or open a PR. Drew reviews the branch and opens the PR; merging it closes the issue.
- Do not leave commented-out code or TODO comments in committed code.
- If you are blocked (missing context, failing tests you cannot fix, external dependency), leave a comment on the issue ending with `_Drafted by Claude Code, an AI agent._` and move on.

# Done

When all actionable issues are complete (or you are blocked on all remaining ones), or the open-issues block at the top of this prompt is empty, output the completion signal:

<promise>COMPLETE</promise>
