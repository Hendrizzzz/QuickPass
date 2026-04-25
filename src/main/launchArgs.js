export function parseLaunchArgs(value) {
    if (value == null || value === '') return []

    if (Array.isArray(value)) {
        return value
            .map(item => String(item ?? '').trim())
            .filter(Boolean)
    }

    const input = String(value)
    const args = []
    let current = ''
    let inQuotes = false
    let escaping = false

    for (let index = 0; index < input.length; index += 1) {
        const char = input[index]

        if (escaping) {
            current += char
            escaping = false
            continue
        }

        if (char === '\\' && input[index + 1] === '"') {
            escaping = true
            continue
        }

        if (char === '"') {
            inQuotes = !inQuotes
            continue
        }

        if (!inQuotes && /\s/.test(char)) {
            if (current) {
                args.push(current)
                current = ''
            }
            continue
        }

        current += char
    }

    if (escaping) current += '\\'
    if (inQuotes) throw new Error('Launch arguments contain an unterminated quote.')
    if (current) args.push(current)

    return args
}
