import type { Config } from "tailwindcss";

export default {
  darkMode: ["class"],
  content: ["./pages/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}", "./app/**/*.{ts,tsx}", "./src/**/*.{ts,tsx}"],
  prefix: "",
  theme: {
    container: {
      center: true,
      padding: "2rem",
      screens: {
        "2xl": "1400px",
      },
    },
    extend: {
      fontFamily: {
        sans: ["Patrick Hand", "cursive", "system-ui", "sans-serif"],
        display: ["Bangers", "cursive"],
        marker: ["Permanent Marker", "cursive"],
        mono: ["JetBrains Mono", "Fira Code", "monospace"],
      },
      colors: {
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        popover: {
          DEFAULT: "hsl(var(--popover))",
          foreground: "hsl(var(--popover-foreground))",
        },
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
        sidebar: {
          DEFAULT: "hsl(var(--sidebar-background))",
          foreground: "hsl(var(--sidebar-foreground))",
          primary: "hsl(var(--sidebar-primary))",
          "primary-foreground": "hsl(var(--sidebar-primary-foreground))",
          accent: "hsl(var(--sidebar-accent))",
          "accent-foreground": "hsl(var(--sidebar-accent-foreground))",
          border: "hsl(var(--sidebar-border))",
          ring: "hsl(var(--sidebar-ring))",
        },
        risk: {
          low: "hsl(var(--risk-low))",
          medium: "hsl(var(--risk-medium))",
          high: "hsl(var(--risk-high))",
        },
        terminal: {
          DEFAULT: "hsl(var(--terminal-bg))",
          text: "hsl(var(--terminal-text))",
        },
        comic: {
          yellow: "hsl(var(--comic-yellow))",
          cyan: "hsl(var(--comic-cyan))",
          magenta: "hsl(var(--comic-magenta))",
          orange: "hsl(var(--comic-orange))",
          pink: "hsl(var(--comic-pink))",
          lime: "hsl(var(--comic-lime))",
          purple: "hsl(var(--comic-purple))",
          teal: "hsl(var(--comic-teal))",
          blue: "hsl(var(--comic-blue))",
          indigo: "hsl(var(--comic-indigo))",
          rose: "hsl(var(--comic-rose))",
          sky: "hsl(var(--comic-sky))",
          amber: "hsl(var(--comic-amber))",
        },
      },
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
        doodle: "4px 12px 4px 12px",
      },
      borderWidth: {
        "3": "3px",
        "4": "4px",
        "5": "5px",
      },
      keyframes: {
        "accordion-down": {
          from: { height: "0" },
          to: { height: "var(--radix-accordion-content-height)" },
        },
        "accordion-up": {
          from: { height: "var(--radix-accordion-content-height)" },
          to: { height: "0" },
        },
        "pulse-ring": {
          "0%": { transform: "scale(0.95)", opacity: "1" },
          "50%": { transform: "scale(1.08)", opacity: "0.5" },
          "100%": { transform: "scale(0.95)", opacity: "1" },
        },
        "scan-line": {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100vh)" },
        },
        "fade-in-up": {
          "0%": { opacity: "0", transform: "translateY(30px) rotate(-3deg)" },
          "100%": { opacity: "1", transform: "translateY(0) rotate(0)" },
        },
        "shimmer": {
          "0%": { backgroundPosition: "-200% 0" },
          "100%": { backgroundPosition: "200% 0" },
        },
        "comic-pop": {
          "0%": { transform: "scale(0) rotate(-15deg)" },
          "60%": { transform: "scale(1.15) rotate(5deg)" },
          "100%": { transform: "scale(1) rotate(0)" },
        },
        "shake": {
          "0%, 100%": { transform: "translateX(0) rotate(0)" },
          "20%": { transform: "translateX(-8px) rotate(-3deg)" },
          "40%": { transform: "translateX(8px) rotate(3deg)" },
          "60%": { transform: "translateX(-6px) rotate(-2deg)" },
          "80%": { transform: "translateX(6px) rotate(2deg)" },
        },
        "float": {
          "0%, 100%": { transform: "translateY(0) rotate(-2deg)" },
          "50%": { transform: "translateY(-15px) rotate(2deg)" },
        },
        "wiggle": {
          "0%, 100%": { transform: "rotate(-3deg)" },
          "50%": { transform: "rotate(3deg)" },
        },
      },
      animation: {
        "accordion-down": "accordion-down 0.2s ease-out",
        "accordion-up": "accordion-up 0.2s ease-out",
        "pulse-ring": "pulse-ring 1.2s ease-in-out infinite",
        "scan-line": "scan-line 2s linear infinite",
        "fade-in-up": "fade-in-up 0.4s cubic-bezier(0.68, -0.55, 0.265, 1.55) forwards",
        "shimmer": "shimmer 2s linear infinite",
        "comic-pop": "comic-pop 0.4s cubic-bezier(0.68, -0.55, 0.265, 1.55) forwards",
        "shake": "shake 0.5s ease-in-out",
        "float": "float 3s ease-in-out infinite",
        "wiggle": "wiggle 1s ease-in-out infinite",
      },
      backgroundImage: {
        "gradient-radial": "radial-gradient(var(--tw-gradient-stops))",
        "grid-pattern": "linear-gradient(hsl(var(--border)) 3px, transparent 3px), linear-gradient(90deg, hsl(var(--border)) 3px, transparent 3px)",
        "speed-lines": "repeating-linear-gradient(85deg, transparent, transparent 15px, hsl(var(--border) / 0.15) 15px, hsl(var(--border) / 0.15) 17px)",
        "halftone": "radial-gradient(circle, hsl(var(--foreground) / 0.12) 1.5px, transparent 1.5px)",
        "crosshatch": "repeating-linear-gradient(45deg, transparent, transparent 4px, hsl(var(--border) / 0.1) 4px, hsl(var(--border) / 0.1) 5px), repeating-linear-gradient(-45deg, transparent, transparent 4px, hsl(var(--border) / 0.1) 4px, hsl(var(--border) / 0.1) 5px)",
      },
      backgroundSize: {
        "grid": "50px 50px",
        "halftone": "10px 10px",
      },
      boxShadow: {
        "comic": "5px 5px 0 hsl(var(--border))",
        "comic-lg": "8px 8px 0 hsl(var(--border))",
        "comic-xl": "12px 12px 0 hsl(var(--border))",
        "comic-primary": "5px 5px 0 hsl(var(--primary))",
        "neon": "0 0 15px hsl(var(--primary)), 0 0 40px hsl(var(--primary) / 0.5)",
        "doodle": "5px 5px 0 hsl(var(--border)), -2px -1px 0 hsl(var(--border))",
      },
    },
  },
  plugins: [require("tailwindcss-animate")],
} satisfies Config;
