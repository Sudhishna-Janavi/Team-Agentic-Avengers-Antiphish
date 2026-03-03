import { defineConfig } from 'vite';
import { resolve } from 'path';
import { viteStaticCopy } from 'vite-plugin-static-copy';

export default defineConfig({
  build: {
    outDir: 'dist',
    rollupOptions: {
      input: {
        // Change 'background.js' to 'extension/background.js'
        background: resolve(__dirname, 'extension/background.js'),
        // If you have a popup, update that too:
        // popup: resolve(__dirname, 'extension/popup.html'),
      },
      output: {
        entryFileNames: '[name].js',
      },
    },
  },
  plugins: [
    viteStaticCopy({
      targets: [
        {
          src: 'node_modules/onnxruntime-web/dist/*.wasm',
          dest: 'lib'
        },
        {
          // Ensure this path matches where your .onnx file actually is
          src: 'extension/model/*.onnx', 
          dest: 'model'
        }
      ]
    })
  ]
});