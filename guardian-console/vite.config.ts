import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 4001,
    host: true, // Bind to 0.0.0.0 to allow access from other devices on the network
  },
});
