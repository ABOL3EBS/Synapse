import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        navy: "#0F172A",
        canvas: "#F8FAFC",
        emerald: {
          DEFAULT: "#10B981",
          dark: "#059669",
          light: "#D1FAE5",
        },
        crimson: {
          DEFAULT: "#B3364A",
          dark: "#8F2A3A",
          light: "#fde8eb",
        },
        amber: {
          DEFAULT: "#F59E0B",
          light: "#FEF3C7",
        },
        danger: {
          DEFAULT: "#EF4444",
          light: "#FEE2E2",
        },
      },
      fontFamily: {
        sans: [
          "-apple-system",
          "BlinkMacSystemFont",
          "SF Pro Display",
          "SF Pro Text",
          "Helvetica Neue",
          "Arial",
          "sans-serif",
        ],
      },
      borderRadius: {
        "2xl": "16px",
        "3xl": "20px",
      },
      boxShadow: {
        card: "0 2px 20px rgba(0,0,0,0.06)",
        "card-hover": "0 4px 28px rgba(0,0,0,0.10)",
        shield: "0 12px 40px rgba(16,185,129,0.30)",
      },
    },
  },
  plugins: [],
} satisfies Config;
