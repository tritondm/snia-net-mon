import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

// Im Entwicklungsmodus (npm run dev) leitet Vite /api inkl. WebSocket an das Rust-Backend weiter.
export default defineConfig({
  plugins: [svelte()],
  server: {
    port: 5173,
    proxy: {
      '/api': { target: 'http://127.0.0.1:8080', ws: true },
    },
  },
  build: { target: 'es2022', chunkSizeWarningLimit: 600 },
});
