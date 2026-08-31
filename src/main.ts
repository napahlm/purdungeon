import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import './style.css'
import { initTokens } from '@/ui/tokens'

// Copy the CSS design tokens into the objects canvas code draws from —
// must happen before anything renders.
initTokens()

const app = createApp(App)
app.use(createPinia())
app.mount('#app')
