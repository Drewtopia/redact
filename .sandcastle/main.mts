// Sequential Reviewer — implement-then-review loop
//
// This template drives a two-phase workflow per issue:
//   Phase 1 (Implement): An agent picks an open issue, works on it
//                        on a dedicated branch, commits the changes, and signals
//                        completion.
//   Phase 2 (Review):    A second agent reviews the branch diff and either
//                        approves it or makes corrections directly on the branch.
//
// Both phases share a single sandbox created via createSandbox(), so the
// implementer and reviewer work on the same explicit branch.
//
// The outer loop repeats up to MAX_ITERATIONS times, processing one issue per
// iteration and stopping early once the backlog is exhausted (an implement
// phase that produces no commits). This is a middle-complexity option between
// the simple-loop (no review gate) and the parallel-planner (concurrent
// execution with a planning phase).
//
// Usage, from the repo root:
//   npm --prefix .sandcastle run sandcastle
// Sandcastle's Node deps live in .sandcastle/package.json so the Rust project stays Node-free.

import * as sandcastle from "@ai-hero/sandcastle";
import { seatbelt } from "@ai-hero/sandcastle/sandboxes/seatbelt";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// Maximum number of implement→review cycles to run before stopping.
// Each cycle works on one issue. Raise this to process more issues per run.
const MAX_ITERATIONS = 10;

// seatbelt() passes only PATH, HOME and TMPDIR and gives the agent a private
// home, so rustup's proxies can't find the toolchain on their own. Point them at
// the host's rustup and cargo homes. Cargo writes its registry cache and lock
// files under CARGO_HOME, so that mount is writable; everything else is read-only.
const home = process.env.HOME!;
const cargoHome = process.env.CARGO_HOME ?? `${home}/.cargo`;
const rustupHome = process.env.RUSTUP_HOME ?? `${home}/.rustup`;
const readonly = (path: string) => ({ hostPath: path, sandboxPath: path, readonly: true });
const sandbox = () =>
  seatbelt({
    env: { CARGO_HOME: cargoHome, RUSTUP_HOME: rustupHome },
    mounts: [
      { hostPath: cargoHome, sandboxPath: cargoHome },
      readonly(rustupHome),
      // The worktree sits under .sandcastle/worktrees/, so cargo walks up to the
      // repo's own Cargo.toml looking for a workspace root and fails if it can't read it.
      readonly(`${process.cwd()}/Cargo.toml`),
      // The git hooks (lefthook.yml) run commit-check and betterleaks, mise tools
      // whose interpreters and install roots sit outside the PATH dirs seatbelt exposes.
      readonly(`${home}/.mise/installs`),
    ],
  });

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------

for (let iteration = 1; iteration <= MAX_ITERATIONS; iteration++) {
  console.log(`\n=== Iteration ${iteration}/${MAX_ITERATIONS} ===\n`);

  // Generate a unique branch name for this iteration.
  const branch = `agent/sandcastle-${Date.now()}`;

  // Create a single sandbox that both the implementer and reviewer share.
  // This gives both agents a real, named branch that persists across phases.
  const sandbox = await sandcastle.createSandbox({
    branch,
    sandbox: sandbox(),
  });

  try {
    // -----------------------------------------------------------------------
    // Phase 1: Implement
    //
    // An agent picks the next open issue, writes the
    // implementation (using RGR: Red → Green → Repeat → Refactor), and
    // commits the result.
    //
    // The agent signals completion via <promise>COMPLETE</promise> when done.
    // -----------------------------------------------------------------------
    // One iteration so each outer pass implements a single issue on its own
    // branch, then hands it to the reviewer. A higher value lets the agent
    // drain the whole backlog onto this one branch in a single pass, which
    // defeats the per-issue review.
    const implement = await sandbox.run({
      name: "implementer",
      maxIterations: 1,
      agent: sandcastle.claudeCode("claude-opus-5-5"),
      promptFile: "./.sandcastle/implement-prompt.md",
    });

    if (!implement.commits.length) {
      // No commits means the backlog is empty or every remaining issue is
      // blocked — there is nothing left to implement or review, so stop.
      console.log("Implementation agent made no commits. Stopping.");
      break;
    }

    console.log(`\nImplementation complete on branch: ${branch}`);
    console.log(`Commits: ${implement.commits.length}`);

    // -----------------------------------------------------------------------
    // Phase 2: Review
    //
    // A second agent reviews the diff of the branch produced by
    // Phase 1. It uses the {{BRANCH}} prompt argument to inspect the right
    // branch, and either approves or makes corrections directly on the branch.
    // -----------------------------------------------------------------------
    await sandbox.run({
      name: "reviewer",
      maxIterations: 1,
      agent: sandcastle.claudeCode("claude-opus-5-5"),
      promptFile: "./.sandcastle/review-prompt.md",
      promptArgs: {
        BRANCH: branch,
      },
    });

    console.log("\nReview complete.");
  } finally {
    await sandbox.close();
  }
}

console.log("\nAll done.");
