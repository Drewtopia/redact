import DefaultTheme from 'vitepress/theme'
import type { Theme } from 'vitepress'
import RedactDemo from './RedactDemo.vue'
import './custom.css'

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    app.component('RedactDemo', RedactDemo)
  },
} satisfies Theme
