import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  // Tauri loads this bundle from its own origin; relative asset URLs keep both
  // the static web deploy and the desktop shell working from one build.
  base: './',
  clearScreen: false,
  server: {
    host: '127.0.0.1',
    port: 1420,
    strictPort: true,
  },
  build: {
    target: 'es2022',
    sourcemap: false,
  },
});
