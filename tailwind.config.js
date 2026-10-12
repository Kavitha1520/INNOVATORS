/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        brand: {
          navy: '#0b1120',
          panel: '#111827',
          cyan: '#67e8f9',
          violet: '#8b5cf6',
          red: '#ef4444',
          orange: '#f59e0b',
          green: '#22c55e',
        },
      },
      boxShadow: {
        glow: '0 0 0 1px rgba(103,232,249,0.35), 0 18px 50px rgba(59,130,246,0.25)',
      },
    },
  },
  plugins: [],
};
