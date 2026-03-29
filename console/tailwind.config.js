/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{vue,js}'],
  theme: {
    fontFamily: {
      sans: ['"Share Tech Mono"', '"Courier New"', 'monospace'],
      mono: ['"Share Tech Mono"', '"Courier New"', 'monospace'],
      vt:   ['"VT323"', 'monospace'],
    },
    extend: {
      colors: {
        retro: {
          green:       '#0a6e0a',
          'green-dim': '#edf7ed',
          'green-mid': '#2d8c2d',
          amber:       '#7a4f00',
          'amber-dim': '#fdf6e3',
          red:         '#8a0f0f',
          'red-dim':   '#fdf0f0',
          bg:          '#f5f5f0',
          panel:       '#ffffff',
          border:      '#d4d4c8',
          cyan:        '#005f7a',
          magenta:     '#7a005f',
        }
      }
    }
  },
  plugins: [],
}

