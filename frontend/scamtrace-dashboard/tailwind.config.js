/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Light "ScamTrace" palette used by the public home page.
        st: {
          navy: "#000b5b",
          "navy-2": "#071c8c",
          blue: "#0074dd",
          "blue-dark": "#005bb0",
          ink: "#0d1841",
          muted: "#454653",
          surface: "#fbf8ff",
          low: "#f3f2ff",
          container: "#ececff",
          high: "#e4e7ff",
          highest: "#dde1ff",
          fixed: "#d6e3ff",
          "fixed-dim": "#a8c8ff",
          outline: "#c6c5d5",
          error: "#ba1a1a",
          "error-bg": "#ffdad6",
          "error-ink": "#93000a",
        },
      },
      fontFamily: {
        manrope: ["Manrope", "system-ui", "sans-serif"],
        inter: ["Inter", "system-ui", "sans-serif"],
      },
    },
  },
  plugins: [],
}
