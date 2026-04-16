/** @type {import('tailwindcss').Config} */
module.exports = {
    content: ['./src/renderer/index.html', './src/renderer/src/**/*.{js,jsx}'],
    theme: {
        extend: {
            colors: {
                dark: {
                    900: '#0a0a0f',
                    800: '#12121a',
                    700: '#1a1a2e',
                    600: '#222240',
                    500: '#2a2a4a'
                },
                accent: {
                    primary: '#6c5ce7',
                    glow: '#a29bfe',
                    success: '#00cec9',
                    danger: '#ff6b6b',
                    warning: '#feca57'
                },
                text: {
                    primary: '#e8e8f0',
                    secondary: '#8888a8',
                    muted: '#555578'
                }
            },
            fontFamily: {
                sans: ['Inter', 'Segoe UI', 'system-ui', '-apple-system', 'sans-serif']
            }
        }
    },
    plugins: []
}
