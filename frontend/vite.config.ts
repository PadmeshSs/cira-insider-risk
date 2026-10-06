/// <reference types="vitest/config" />
import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// The dashboard talks to the Chapter 13 API. VITE_API_BASE_URL overrides the
// default (http://localhost:8000/api/v1); CORS on the backend already allows
// the Vite dev origin (CORS_ORIGINS=http://localhost:5173).
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  server: { port: 5173 },
  // MUI + Emotion + React land in one ~600 kB entry chunk; route views and
  // the chart library are split off and load on demand.
  build: { chunkSizeWarningLimit: 700 },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    css: false,
    // Playwright specs (Chapter 15 click-through) run under `npm run test:e2e`, not Vitest.
    exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
  },
})
