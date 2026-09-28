/**
 * Tailwind-Theme im Hyprland/Wayland-Stil mit der Catppuccin-Mocha-Palette.
 * https://catppuccin.com/palette – Mocha (dunkel). Pastell-Akzente: teal, mauve, sapphire.
 */
const mocha = {
  rosewater: '#f5e0dc',
  flamingo: '#f2cdcd',
  pink: '#f5c2e7',
  mauve: '#cba6f7',
  red: '#f38ba8',
  maroon: '#eba0ac',
  peach: '#fab387',
  yellow: '#f9e2af',
  green: '#a6e3a1',
  teal: '#94e2d5',
  sky: '#89dceb',
  sapphire: '#74c7ec',
  blue: '#89b4fa',
  lavender: '#b4befe',
  text: '#cdd6f4',
  subtext1: '#bac2de',
  subtext0: '#a6adc8',
  overlay2: '#9399b2',
  overlay1: '#7f849c',
  overlay0: '#6c7086',
  surface2: '#585b70',
  surface1: '#45475a',
  surface0: '#313244',
  base: '#1e1e2e',
  mantle: '#181825',
  crust: '#11111b',
};

/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{svelte,js}'],
  theme: {
    extend: {
      colors: { ctp: mocha },
      fontFamily: {
        mono: ['"Twemoji Country Flags"', '"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      borderRadius: {
        // Hyprland: decoration { rounding = 12 }
        window: '0.75rem',
      },
      boxShadow: {
        // weicher Schatten + Glow der aktiven Fensterkante
        window: '0 8px 32px -8px rgb(17 17 27 / 0.8)',
        glow: '0 0 0 1px rgb(148 226 213 / 0.35), 0 0 24px -4px rgb(148 226 213 / 0.35)',
        'glow-mauve': '0 0 0 1px rgb(203 166 247 / 0.35), 0 0 24px -4px rgb(203 166 247 / 0.3)',
        'glow-red': '0 0 0 1px rgb(243 139 168 / 0.45), 0 0 18px -4px rgb(243 139 168 / 0.45)',
      },
      backgroundImage: {
        // Hyprland: col.active_border = rgba(94e2d5ee) rgba(cba6f7ee) 45deg
        'active-border': 'linear-gradient(135deg, #94e2d5, #74c7ec 45%, #cba6f7)',
        wallpaper:
          'radial-gradient(1200px 600px at 10% -10%, rgb(203 166 247 / 0.18), transparent 60%),' +
          'radial-gradient(900px 500px at 110% 10%, rgb(116 199 236 / 0.16), transparent 60%),' +
          'radial-gradient(800px 600px at 50% 120%, rgb(148 226 213 / 0.12), transparent 60%)',
      },
      keyframes: {
        pulseDot: { '0%, 100%': { opacity: 1 }, '50%': { opacity: 0.35 } },
        fadeIn: { from: { opacity: 0, transform: 'translateY(4px) scale(0.99)' }, to: { opacity: 1, transform: 'none' } },
      },
      animation: {
        'pulse-dot': 'pulseDot 1.6s ease-in-out infinite',
        // Hyprland: animation = windows, 1, 4, default, popin 90%
        popin: 'fadeIn 180ms cubic-bezier(0.05, 0.9, 0.1, 1.05)',
      },
    },
  },
  plugins: [],
};
