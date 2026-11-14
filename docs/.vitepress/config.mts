import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'redact',
  description: 'Keep secrets, names, and sensitive information out of what AI sees',
  base: '/redact/',
  // Setup for contributors' coding agents, not pages for readers.
  srcExclude: ['agents/**'],
  cleanUrls: true,
  lastUpdated: true,
  themeConfig: {
    nav: [
      { text: 'Guide', link: '/guide/getting-started' },
      { text: 'Packs', link: '/packs/' },
      { text: 'Reference', link: '/reference/config' },
    ],
    sidebar: [
      {
        text: 'Guide',
        items: [
          { text: 'Getting started', link: '/guide/getting-started' },
          { text: 'With Claude Code', link: '/guide/claude-code' },
          { text: 'With other agents', link: '/guide/agents' },
          { text: 'With fnox and mise', link: '/guide/fnox-mise' },
          { text: 'With .env files', link: '/guide/dotenv' },
          { text: 'Hiding yourself', link: '/guide/me' },
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
