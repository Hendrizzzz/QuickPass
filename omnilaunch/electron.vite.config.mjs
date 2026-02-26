import { resolve } from 'path'
import { defineConfig, externalizeDepsPlugin } from 'electron-vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
    main: {
        plugins: [externalizeDepsPlugin({ exclude: ['electron'] })],
        build: {
            rollupOptions: {
                external: ['electron'],
                output: {
                    format: 'cjs',
                    interop: 'auto'
                }
            }
        }
    },
    preload: {
        plugins: [externalizeDepsPlugin({ exclude: ['electron'] })],
        build: {
            rollupOptions: {
                external: ['electron'],
                output: {
                    format: 'cjs',
                    interop: 'auto'
                }
            }
        }
    },
    renderer: {
        resolve: {
            alias: {
                '@': resolve('src/renderer/src')
            }
        },
        plugins: [react()]
    }
})
