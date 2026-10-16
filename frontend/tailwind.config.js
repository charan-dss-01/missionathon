/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        obsidian: {
          DEFAULT: "#080B10",
          light: "#0E131C",
          dark: "#040608"
        },
        panel: {
          DEFAULT: "#101720",
          subtle: "#0D131B",
          border: "#1C2738",
          hover: "#151F2C"
        },
        cyan: {
          glow: "#4DEBFF",
          DEFAULT: "#38BDF8",
          dark: "#0284C7"
        },
        acid: {
          DEFAULT: "#C7FF5E",
          hover: "#B5F540",
          dim: "#88B834"
        },
        threat: {
          critical: "#FF5364",
          high: "#FF6B6B",
          medium: "#FFBF69",
          low: "#4DEBFF",
          safe: "#C7FF5E"
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Menlo', 'Monaco', 'Courier New', 'monospace'],
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
      },
      boxShadow: {
        'glow-cyan': '0 0 20px -5px rgba(77, 235, 255, 0.3)',
        'glow-acid': '0 0 20px -5px rgba(199, 255, 94, 0.3)',
        'glow-danger': '0 0 20px -5px rgba(255, 83, 100, 0.35)',
      }
    },
  },
  plugins: [],
};
