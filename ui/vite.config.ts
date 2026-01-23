import preact from '@preact/preset-vite';
import { visualizer } from 'rollup-plugin-visualizer';
import { defineConfig } from 'vite';

const analyze = ['1', 'true', 'yes', 'on'].includes(String(process.env.ANALYZE || '').trim().toLowerCase());
const plugins = [preact()];

if (analyze) {
  plugins.push(
    visualizer({
      filename: 'dist/bundle-stats.html',
      template: 'treemap',
      gzipSize: true,
      brotliSize: true,
      open: false
    })
  );
}

export default defineConfig({
  plugins,
  build: {
    target: 'es2020',
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('/node_modules/@xterm/')) return 'xterm';
        }
      }
    }
  }
});
