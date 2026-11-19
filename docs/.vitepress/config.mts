import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'redact',
  description: 'Keep secrets, names, and sensitive information out of what AI sees',
  base: '/redact/',
  // Setup for contributors' coding agents, and research notes that link into
  // the source tree: not pages for readers.
  srcExclude: ['agents/**', 'research/**'],
  cleanUrls: true,
  lastUpdated: true,
  themeConfig: {
    nav: [
      { text: 'Guide', link: '/guide/getting-started' },
      { text: 'Integrations', link: '/integrations/' },
      { text: 'Packs', link: '/packs/' },
      { text: 'Reference', link: '/reference/config' },
    ],
    sidebar: [
      {
        text: 'Guide',
        items: [
          { text: 'Getting started', link: '/guide/getting-started' },
          { text: 'See it work', link: '/guide/see-it-work' },
          { text: 'Hide environment variables', link: '/guide/env' },
          { text: 'Hide .env files', link: '/guide/dotenv' },
          { text: 'Hide yourself', link: '/guide/me' },
          { text: 'Use with any tool', link: '/guide/any-tool' },
        ],
      },
      {
        text: 'Integrations',
        items: [
          { text: 'Overview', link: '/integrations/' },
          { text: 'Claude Code', link: '/integrations/claude-code' },
          { text: 'Codex CLI', link: '/integrations/codex' },
          { text: 'Chat windows', link: '/integrations/clipboard' },
          { text: 'Git hooks and CI', link: '/integrations/git-ci' },
          { text: 'fnox', link: '/integrations/fnox' },
          { text: 'mise', link: '/integrations/mise' },
        ],
      },
      {
        text: 'Packs',
        items: [
          { text: 'How packs work', link: '/packs/' },
          { text: 'azure', link: '/packs/azure' },
          { text: 'identity', link: '/packs/identity' },
          { text: 'kubernetes', link: '/packs/kubernetes' },
          { text: 'docker', link: '/packs/docker' },
          { text: 'npm', link: '/packs/npm' },
          { text: 'http', link: '/packs/http' },
          { text: 'gcp', link: '/packs/gcp' },
          { text: 'credentials', link: '/packs/credentials' },
          { text: 'pii', link: '/packs/pii' },
          { text: 'Writing a pack', link: '/packs/writing' },
        ],
      },
      {
        text: 'Reference',
        items: [
          { text: 'Configuration', link: '/reference/config' },
          { text: 'CLI', link: '/reference/cli' },
          { text: 'How it works', link: '/reference/how-it-works' },
          { text: 'Limits', link: '/reference/limits' },
          { text: 'Prior art and thanks', link: '/reference/thanks' },
        ],
      },
    ],
    socialLinks: [{ icon: 'github', link: 'https://github.com/Drewtopia/redact' }],
    editLink: { pattern: 'https://github.com/Drewtopia/redact/edit/main/docs/:path' },
    search: { provider: 'local' },
    footer: { message: 'MIT or Apache-2.0. Work in progress: check the output before you share it.' },
  },
})
