import { resolve } from 'path'
import { defineConfig, externalizeDepsPlugin } from 'electron-vite'
import react from '@vitejs/plugin-react'
import obfuscator from 'vite-plugin-javascript-obfuscator'

const obfuscatorConfig = {
    include: ['src/**/*.js', 'src/**/*.jsx'],
    exclude: [/node_modules/],
    apply: 'build',
    debugger: true,
    options: {
        compact: true,
        controlFlowFlattening: true,
        controlFlowFlatteningThreshold: 0.75,
        deadCodeInjection: true,
        deadCodeInjectionThreshold: 0.4,
        stringArray: true,
        stringArrayEncoding: ['base64'],
        stringArrayThreshold: 0.75
    }
}

export default defineConfig({
    main: {
        plugins: [
            externalizeDepsPlugin({ exclude: ['electron'] }),
            obfuscator(obfuscatorConfig)
        ],
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
        plugins: [
            externalizeDepsPlugin({ exclude: ['electron'] }),
            obfuscator(obfuscatorConfig)
        ],
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
        plugins: [
            react(),
            obfuscator(obfuscatorConfig)
        ]
    }
})
