import type { Config } from 'tailwindcss';

const config: Config = {
  content: ['./app/**/*.{ts,tsx}', './components/**/*.{ts,tsx}', './lib/**/*.{ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['var(--font-inter)', 'sans-serif']
      },
      boxShadow: {
        glow: '0 0 0 1px rgba(6, 182, 212, 0.15), 0 18px 60px rgba(2, 6, 23, 0.45)'
      }
    }
  },
  plugins: []
};

export default config;
