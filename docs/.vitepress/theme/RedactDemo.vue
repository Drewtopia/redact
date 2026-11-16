<script setup lang="ts">
// A walk-through of what the Claude Code mod does with one secret. It runs in
// the browser with a few simple rules, not redact's packs, and sends nothing.
import { computed, ref } from 'vue'

const sample = `$ git log -1
Author: Ana Silva <ana.silva@example.com>
    Fix the deploy script

$ cat .env
ACME_API_KEY=acme_7Kq2Lm9Px4Rt8Vw
DATABASE_PASSWORD=blue-falcon-42`

const RULES: [string, RegExp][] = [
  ['PERSON', /^Author:\s+([^<\n]+?)\s+</gm],
  ['EMAIL', /([\w.+-]+@[\w-]+(?:\.[\w-]+)+)/g],
  ['SECRET', /\b[\w-]*(?:password|passwd|secret|token|key)\b\s*[=:]\s*["']?([^\s"']+)/gi],
  ['SECRET', /:\/\/[^:\s/@]+:([^@\s/]+)@/g],
]

const text = ref(sample)
const step = ref(0)
// A fresh key for each visit, as redact makes one for each run.
const salt = Math.random().toString(36).slice(2)

function tagFor(label: string, value: string): string {
  let h = 0x811c9dc5
  for (const c of salt + label + value) h = Math.imul(h ^ c.charCodeAt(0), 0x01000193) >>> 0
  return `[${label}-${h.toString(16).padStart(8, '0')}]`
}

type Part = { text: string; tag?: string }

const parts = computed<Part[]>(() => {
  const s = text.value
  const spans: { start: number; end: number; label: string }[] = []
  for (const [label, re] of RULES) {
    for (const m of s.matchAll(re)) {
      const start = m.index! + m[0].indexOf(m[1]!)
      spans.push({ start, end: start + m[1]!.length, label })
    }
  }
  spans.sort((a, b) => a.start - b.start || b.end - a.end)
  const out: Part[] = []
  let p = 0
  for (const sp of spans) {
    if (sp.start < p) continue
    if (sp.start > p) out.push({ text: s.slice(p, sp.start) })
    const value = s.slice(sp.start, sp.end)
    out.push({ text: value, tag: tagFor(sp.label, value) })
    p = sp.end
  }
  if (p < s.length) out.push({ text: s.slice(p) })
  return out
})

// The value the rest of the walk-through uses: the first secret, else any.
const pick = computed(() => {
  const hidden = parts.value.filter((x) => x.tag)
  return hidden.find((x) => x.tag!.startsWith('[SECRET')) ?? hidden[0]
})

const STEPS = ['Your text', 'What Claude sees', 'Claude uses a tag', 'Your computer runs it', 'The answer, hidden again']
</script>

<template>
  <div class="demo">
    <ol class="steps">
      <li v-for="(name, i) in STEPS" :key="name">
        <button type="button" :aria-current="i === step ? 'step' : undefined" @click="step = i">
          <span class="n">{{ i + 1 }}</span> {{ name }}
        </button>
      </li>
    </ol>

    <div class="panel">
      <template v-if="step === 0">
        <p>This is the output you are about to give Claude. Change it if you like, but use made-up values.</p>
        <textarea v-model="text" rows="9" spellcheck="false" aria-label="Text to hide"></textarea>
      </template>

      <template v-else-if="step === 1">
        <p>redact swaps each name, email and key for a tag. The same value always gets the same tag, so Claude can still follow the text.</p>
        <pre><template v-for="(x, i) in parts" :key="i"><mark v-if="x.tag" class="tag">{{ x.tag }}</mark><template v-else>{{ x.text }}</template></template></pre>
      </template>

      <p v-else-if="!pick" class="empty">Nothing in your text was hidden. Go back to step 1 and add a value, such as <code>password=made-up-1</code>.</p>

      <template v-else-if="step === 2">
        <p>Claude needs the key to do a job. It only has the tag, so it writes the tag into the command.</p>
        <div class="who">Claude writes</div>
        <pre>./deploy.sh --key <mark class="tag">{{ pick.tag }}</mark></pre>
      </template>

      <template v-else-if="step === 3">
        <p>Just before the command runs, the Claude Code mod looks the tag up and puts the real value in. The real value comes from a list the mod keeps in memory on your computer. Claude never sees this line.</p>
        <div class="who">Your computer runs</div>
        <pre>./deploy.sh --key <mark class="real">{{ pick.text }}</mark></pre>
      </template>

      <template v-else>
        <p>The command prints the real value back. The mod hides it again before Claude reads the answer.</p>
        <div class="who">The command prints</div>
        <pre>Deployed with key <mark class="real">{{ pick.text }}</mark></pre>
        <div class="who">Claude reads</div>
        <pre>Deployed with key <mark class="tag">{{ pick.tag }}</mark></pre>
      </template>
    </div>

    <div class="nav">
      <button type="button" :disabled="step === 0" @click="step--">Back</button>
      <button type="button" :disabled="step === STEPS.length - 1" @click="step++">Next</button>
    </div>
  </div>
</template>

<style scoped>
.demo {
  margin: 24px 0;
  border: 1px solid var(--vp-c-divider);
  border-radius: 12px;
  padding: 16px;
  background: var(--vp-c-bg-soft);
}
.steps {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  list-style: none;
  padding: 0;
  margin: 0 0 12px;
}
.steps li {
  margin: 0;
}
.steps button {
  border: 1px solid var(--vp-c-divider);
  border-radius: 20px;
  padding: 4px 12px;
  font-size: 13px;
  color: var(--vp-c-text-2);
  background: var(--vp-c-bg);
}
.steps button[aria-current] {
  border-color: var(--vp-c-brand-1);
  color: var(--vp-c-brand-1);
  background: var(--vp-c-brand-soft);
}
.n {
  font-weight: 600;
}
.panel p {
  margin: 0 0 12px;
}
.who {
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--vp-c-text-2);
  margin: 12px 0 4px;
}
textarea,
pre {
  width: 100%;
  box-sizing: border-box;
  margin: 0;
  padding: 12px;
  border: 1px solid var(--vp-c-divider);
  border-radius: 8px;
  background: var(--vp-c-bg);
  color: var(--vp-c-text-1);
  font-family: var(--vp-font-family-mono);
  font-size: 13px;
  line-height: 1.6;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
textarea {
  resize: vertical;
}
mark {
  border-radius: 4px;
  padding: 0 2px;
}
.tag {
  background: var(--vp-c-brand-soft);
  color: var(--vp-c-brand-1);
}
.real {
  background: var(--vp-c-warning-soft);
  color: var(--vp-c-warning-1);
}
.empty {
  color: var(--vp-c-text-2);
}
.nav {
  display: flex;
  justify-content: space-between;
  margin-top: 12px;
}
.nav button {
  border: 1px solid var(--vp-c-brand-1);
  border-radius: 8px;
  padding: 4px 16px;
  color: var(--vp-c-brand-1);
  font-weight: 500;
}
.nav button:disabled {
  border-color: var(--vp-c-divider);
  color: var(--vp-c-text-3);
  cursor: default;
}
</style>
