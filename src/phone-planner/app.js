import {
    PHONE_ACCOUNT_STATES,
    PHONE_DRAFT_LIMITS,
    createAccountIntention,
    createBrowserProfileSlot,
    createBrowserTab,
    createDesiredAppPlaceholder,
    createDraftInState,
    createPhonePlannerState,
    deleteDraftFromState,
    duplicateDraftInState,
    exportCloudDraftJson,
    validateDraftForExport
} from './phonePlannerCore.js'
import {
    loadPhonePlannerState,
    savePhonePlannerState
} from './phonePlannerStorage.js'

let state = loadPhonePlannerState()
let statusMessage = state.loadError || 'Saved locally on this browser.'
let errorMessage = ''
let lastExportJson = ''

const root = document.getElementById('app')

if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('./service-worker.js').catch(() => {})
}

function selectedDraft() {
    return state.drafts.find(draft => draft.draftId === state.selectedDraftId) || null
}

function createElement(tag, attrs = {}, children = []) {
    const element = document.createElement(tag)
    for (const [key, value] of Object.entries(attrs)) {
        if (key === 'className') {
            element.className = value
        } else if (key === 'text') {
            element.textContent = value
        } else if (key === 'value') {
            element.value = value
        } else if (key === 'checked') {
            element.checked = !!value
        } else if (key === 'disabled') {
            element.disabled = !!value
        } else if (key === 'dataset') {
            for (const [dataKey, dataValue] of Object.entries(value || {})) {
                element.dataset[dataKey] = dataValue
            }
        } else if (key.startsWith('on') && typeof value === 'function') {
            element.addEventListener(key.slice(2).toLowerCase(), value)
        } else if (value !== false && value != null) {
            element.setAttribute(key, String(value))
        }
    }

    const childList = Array.isArray(children) ? children : [children]
    for (const child of childList) {
        if (child == null) continue
        if (typeof child === 'string') {
            element.appendChild(document.createTextNode(child))
        } else {
            element.appendChild(child)
        }
    }
    return element
}

function fieldLabel(text, child, hint = '') {
    return createElement('label', { className: 'field' }, [
        createElement('span', { className: 'field-label', text }),
        child,
        hint ? createElement('small', { text: hint }) : null
    ])
}

function textInput({ label, value, maxLength, placeholder = '', onInput, hint = '', type = 'text', inputMode = '' }) {
    return fieldLabel(label, createElement('input', {
        type,
        value: value || '',
        maxLength,
        placeholder,
        inputMode,
        onInput: event => onInput(event.target.value)
    }), hint)
}

function textArea({ label, value, maxLength, placeholder = '', rows = 3, onInput, hint = '' }) {
    return fieldLabel(label, createElement('textarea', {
        value: value || '',
        maxLength,
        placeholder,
        rows,
        onInput: event => onInput(event.target.value)
    }), hint)
}

function selectInput({ label, value, options, onChange, hint = '' }) {
    const select = createElement('select', {
        value: value || '',
        onChange: event => onChange(event.target.value)
    }, options.map(option => createElement('option', {
        value: option.value,
        text: option.label
    })))
    select.value = value || ''
    return fieldLabel(label, select, hint)
}

function checkboxInput({ label, checked, onChange }) {
    return createElement('label', { className: 'check-row' }, [
        createElement('input', {
            type: 'checkbox',
            checked,
            onChange: event => onChange(event.target.checked)
        }),
        createElement('span', { text: label })
    ])
}

function button(text, className, onClick, disabled = false) {
    return createElement('button', { className, onClick, disabled, text })
}

function saveCurrent(message = 'Saved locally on this browser.', options = {}) {
    try {
        state = savePhonePlannerState(state, options)
        statusMessage = message
        errorMessage = ''
    } catch (err) {
        errorMessage = err?.message || 'Could not save local draft.'
    }
    renderStatus()
}

function commitState(nextState, message, options = {}) {
    state = nextState
    saveCurrent(message, options)
    render()
}

function mutateSelectedDraft(mutator, { rerender = false, message = 'Saved locally on this browser.' } = {}) {
    const draft = selectedDraft()
    if (!draft) return
    try {
        mutator(draft)
    } catch (err) {
        errorMessage = err?.message || 'Draft edit failed.'
        renderStatus()
        return
    }
    draft.updatedAt = Date.now()
    saveCurrent(message)
    if (rerender) render()
}

function optionsForProfiles(draft) {
    return [
        { value: '', label: 'No profile intention' },
        ...draft.browserProfileSlots.map(profile => ({
            value: profile.id,
            label: profile.label || profile.id
        }))
    ]
}

function optionsForAccounts(draft) {
    return [
        { value: '', label: 'No account intention' },
        ...draft.accountSlots.map(account => ({
            value: account.id,
            label: account.label || account.id
        }))
    ]
}

function renderStatus() {
    const node = document.getElementById('status-line')
    if (!node) return
    node.className = errorMessage ? 'status error' : 'status'
    node.textContent = errorMessage || statusMessage
}

function renderHeader() {
    return createElement('header', { className: 'app-header' }, [
        createElement('div', {}, [
            createElement('p', { className: 'eyebrow', text: 'Wipesnap Phone Planner' }),
            createElement('h1', { text: 'Local Draft Planner' }),
            createElement('p', {
                className: 'subhead',
                text: 'Drafts stay in this browser until you export JSON. Account slots are intentions only, not Google credentials or copied login sessions.'
            })
        ]),
        createElement('div', { className: 'offline-pill', text: 'Offline local' })
    ])
}

function renderDraftPicker(draft) {
    const select = createElement('select', {
        value: state.selectedDraftId,
        onChange: event => {
            state.selectedDraftId = event.target.value
            saveCurrent('Selected draft saved locally.')
            render()
        }
    }, state.drafts.map(item => createElement('option', {
        value: item.draftId,
        text: item.name || item.draftId
    })))
    select.value = state.selectedDraftId

    return createElement('section', { className: 'toolbar-panel' }, [
        createElement('div', { className: 'draft-select' }, [
            createElement('span', { className: 'field-label', text: 'Draft' }),
            select
        ]),
        createElement('div', { className: 'toolbar-actions' }, [
            button('New', 'btn primary', () => {
                try {
                    commitState(createDraftInState(state, { name: 'Untitled Draft' }), 'Created local draft.')
                } catch (err) {
                    errorMessage = err.message
                    renderStatus()
                }
            }, state.drafts.length >= PHONE_DRAFT_LIMITS.maxActiveDraftsPerUser),
            button('Duplicate', 'btn', () => {
                if (!draft) return
                try {
                    commitState(duplicateDraftInState(state, draft.draftId), 'Duplicated local draft.')
                } catch (err) {
                    errorMessage = err.message
                    renderStatus()
                }
            }, !draft || state.drafts.length >= PHONE_DRAFT_LIMITS.maxActiveDraftsPerUser),
            button('Delete', 'btn danger', () => {
                if (!draft) return
                if (!window.confirm(`Delete "${draft.name || 'this draft'}" from this browser?`)) return
                commitState(deleteDraftFromState(state, draft.draftId, { createIfEmpty: false }), 'Deleted local draft.', { createIfEmpty: false })
            }, !draft)
        ])
    ])
}

function renderDraftDetails(draft) {
    return createElement('section', { className: 'panel' }, [
        createElement('div', { className: 'section-head' }, [
            createElement('h2', { text: 'Draft Details' }),
            createElement('span', { text: `${state.drafts.length}/${PHONE_DRAFT_LIMITS.maxActiveDraftsPerUser} drafts` })
        ]),
        createElement('div', { className: 'grid two' }, [
            textInput({
                label: 'Draft name',
                value: draft.name,
                maxLength: PHONE_DRAFT_LIMITS.maxDraftNameLength,
                onInput: value => mutateSelectedDraft(next => { next.name = value })
            }),
            checkboxInput({
                label: 'Default draft',
                checked: draft.isDefault,
                onChange: value => mutateSelectedDraft(next => { next.isDefault = value })
            })
        ]),
        textArea({
            label: 'Notes',
            value: draft.notes,
            maxLength: PHONE_DRAFT_LIMITS.maxDraftNotesLength,
            rows: 4,
            placeholder: 'Local planning notes only. Do not enter passwords, tokens, paths, scripts, or recovery codes.',
            onInput: value => mutateSelectedDraft(next => { next.notes = value })
        })
    ])
}

function renderProfileSection(draft) {
    return createElement('section', { className: 'panel' }, [
        createElement('div', { className: 'section-head' }, [
            createElement('h2', { text: 'Browser Profile Intentions' }),
            createElement('span', { text: `${draft.browserProfileSlots.length}/${PHONE_DRAFT_LIMITS.maxBrowserProfileSlots}` })
        ]),
        createElement('p', {
            className: 'helper',
            text: 'Profile slots are labels for desktop verification later. They do not create browser profiles from the phone.'
        }),
        button('Add profile slot', 'btn small', () => {
            mutateSelectedDraft(next => {
                if (next.browserProfileSlots.length >= PHONE_DRAFT_LIMITS.maxBrowserProfileSlots) throw new Error('Profile slot limit reached.')
                next.browserProfileSlots.push(createBrowserProfileSlot({ label: `Profile ${next.browserProfileSlots.length + 1}` }))
            }, { rerender: true, message: 'Added profile intention.' })
        }, draft.browserProfileSlots.length >= PHONE_DRAFT_LIMITS.maxBrowserProfileSlots),
        createElement('div', { className: 'item-list' }, draft.browserProfileSlots.map(profile => renderProfileItem(draft, profile)))
    ])
}

function renderProfileItem(draft, profile) {
    return createElement('article', { className: 'item' }, [
        createElement('div', { className: 'grid two' }, [
            textInput({
                label: 'Profile label',
                value: profile.label,
                maxLength: PHONE_DRAFT_LIMITS.maxBrowserProfileSlotLabelLength,
                onInput: value => mutateSelectedDraft(next => {
                    const item = next.browserProfileSlots.find(slot => slot.id === profile.id)
                    if (item) item.label = value
                })
            }),
            fieldLabel('Provider', createElement('input', { value: 'google', disabled: true }))
        ]),
        button('Remove profile', 'btn danger small', () => {
            mutateSelectedDraft(next => {
                next.browserProfileSlots = next.browserProfileSlots.filter(slot => slot.id !== profile.id)
                for (const account of next.accountSlots) {
                    if (account.profileSlotId === profile.id) account.profileSlotId = ''
                }
                for (const tab of next.browserTabs) {
                    if (tab.profileSlotId === profile.id) tab.profileSlotId = ''
                }
            }, { rerender: true, message: 'Removed profile intention.' })
        })
    ])
}

function renderAccountSection(draft) {
    return createElement('section', { className: 'panel' }, [
        createElement('div', { className: 'section-head' }, [
            createElement('h2', { text: 'Google Account Intentions' }),
            createElement('span', { text: `${draft.accountSlots.length}/${PHONE_DRAFT_LIMITS.maxAccountIntentions}` })
        ]),
        createElement('p', {
            className: 'helper',
            text: 'Use these as planning labels. Wipesnap will still need the desktop browser to verify sign-in later.'
        }),
        button('Add account intention', 'btn small', () => {
            mutateSelectedDraft(next => {
                if (next.accountSlots.length >= PHONE_DRAFT_LIMITS.maxAccountIntentions) throw new Error('Account intention limit reached.')
                next.accountSlots.push(createAccountIntention({
                    label: `Google ${next.accountSlots.length + 1}`,
                    profileSlotId: next.browserProfileSlots[0]?.id || '',
                    state: 'needs-check'
                }))
            }, { rerender: true, message: 'Added account intention.' })
        }, draft.accountSlots.length >= PHONE_DRAFT_LIMITS.maxAccountIntentions),
        createElement('div', { className: 'item-list' }, draft.accountSlots.map(account => renderAccountItem(draft, account)))
    ])
}

function renderAccountItem(draft, account) {
    return createElement('article', { className: 'item' }, [
        createElement('div', { className: 'grid two' }, [
            textInput({
                label: 'Label',
                value: account.label,
                maxLength: PHONE_DRAFT_LIMITS.maxAccountIntentionLabelLength,
                onInput: value => mutateSelectedDraft(next => {
                    const item = next.accountSlots.find(slot => slot.id === account.id)
                    if (item) item.label = value
                })
            }),
            textInput({
                label: 'Identifier hint',
                value: account.identifierHint,
                maxLength: PHONE_DRAFT_LIMITS.maxAccountIdentifierHintLength,
                placeholder: 'optional masked email',
                onInput: value => mutateSelectedDraft(next => {
                    const item = next.accountSlots.find(slot => slot.id === account.id)
                    if (item) item.identifierHint = value
                })
            })
        ]),
        createElement('div', { className: 'grid two' }, [
            selectInput({
                label: 'State',
                value: account.state,
                options: PHONE_ACCOUNT_STATES.map(value => ({ value, label: value })),
                onChange: value => mutateSelectedDraft(next => {
                    const item = next.accountSlots.find(slot => slot.id === account.id)
                    if (item) item.state = value
                }, { rerender: true })
            }),
            selectInput({
                label: 'Profile intention',
                value: account.profileSlotId,
                options: optionsForProfiles(draft),
                onChange: value => mutateSelectedDraft(next => {
                    const item = next.accountSlots.find(slot => slot.id === account.id)
                    if (item) item.profileSlotId = value
                }, { rerender: true })
            })
        ]),
        button('Remove account', 'btn danger small', () => {
            mutateSelectedDraft(next => {
                next.accountSlots = next.accountSlots.filter(slot => slot.id !== account.id)
                for (const tab of next.browserTabs) {
                    if (tab.accountSlotId === account.id) tab.accountSlotId = ''
                }
            }, { rerender: true, message: 'Removed account intention.' })
        })
    ])
}

function renderTabsSection(draft) {
    const orderedTabs = [...draft.browserTabs].sort((a, b) => Number(a.order || 0) - Number(b.order || 0))
    return createElement('section', { className: 'panel wide' }, [
        createElement('div', { className: 'section-head' }, [
            createElement('h2', { text: 'Browser Tabs' }),
            createElement('span', { text: `${draft.browserTabs.length}/${PHONE_DRAFT_LIMITS.maxBrowserTabs}` })
        ]),
        button('Add AI Studio tab', 'btn small', () => {
            mutateSelectedDraft(next => {
                if (next.browserTabs.length >= PHONE_DRAFT_LIMITS.maxBrowserTabs) throw new Error('Browser tab limit reached.')
                next.browserTabs.push(createBrowserTab({
                    order: next.browserTabs.length,
                    accountSlotId: next.accountSlots[0]?.id || '',
                    profileSlotId: next.browserProfileSlots[0]?.id || ''
                }))
            }, { rerender: true, message: 'Added browser tab.' })
        }, draft.browserTabs.length >= PHONE_DRAFT_LIMITS.maxBrowserTabs),
        createElement('div', { className: 'item-list' }, orderedTabs.map(tab => renderTabItem(draft, tab, orderedTabs)))
    ])
}

function moveTab(tabId, direction) {
    mutateSelectedDraft(next => {
        const ordered = [...next.browserTabs].sort((a, b) => Number(a.order || 0) - Number(b.order || 0))
        const index = ordered.findIndex(tab => tab.id === tabId)
        const other = ordered[index + direction]
        if (!other) return
        const tab = ordered[index]
        const order = tab.order
        tab.order = other.order
        other.order = order
    }, { rerender: true, message: 'Updated tab order.' })
}

function renderTabItem(draft, tab, orderedTabs) {
    const position = orderedTabs.findIndex(item => item.id === tab.id)
    return createElement('article', { className: 'item tab-item' }, [
        createElement('div', { className: 'item-topline' }, [
            createElement('strong', { text: `Tab ${position + 1}` }),
            createElement('div', { className: 'inline-actions' }, [
                button('Up', 'btn tiny', () => moveTab(tab.id, -1), position === 0),
                button('Down', 'btn tiny', () => moveTab(tab.id, 1), position === orderedTabs.length - 1)
            ])
        ]),
        createElement('div', { className: 'grid two' }, [
            textInput({
                label: 'URL',
                value: tab.url,
                maxLength: PHONE_DRAFT_LIMITS.maxBrowserTabUrlLength,
                placeholder: 'https://aistudio.google.com/',
                onInput: value => mutateSelectedDraft(next => {
                    const item = next.browserTabs.find(candidate => candidate.id === tab.id)
                    if (item) item.url = value
                })
            }),
            textInput({
                label: 'Label',
                value: tab.label,
                maxLength: PHONE_DRAFT_LIMITS.maxBrowserTabLabelLength,
                onInput: value => mutateSelectedDraft(next => {
                    const item = next.browserTabs.find(candidate => candidate.id === tab.id)
                    if (item) item.label = value
                })
            })
        ]),
        createElement('div', { className: 'grid three' }, [
            textInput({
                label: 'Order',
                value: String(tab.order ?? 0),
                maxLength: 4,
                inputMode: 'numeric',
                onInput: value => mutateSelectedDraft(next => {
                    const item = next.browserTabs.find(candidate => candidate.id === tab.id)
                    if (item) item.order = Math.max(0, Number.parseInt(value, 10) || 0)
                })
            }),
            selectInput({
                label: 'Account',
                value: tab.accountSlotId,
                options: optionsForAccounts(draft),
                onChange: value => mutateSelectedDraft(next => {
                    const item = next.browserTabs.find(candidate => candidate.id === tab.id)
                    if (item) item.accountSlotId = value
                }, { rerender: true })
            }),
            selectInput({
                label: 'Profile',
                value: tab.profileSlotId,
                options: optionsForProfiles(draft),
                onChange: value => mutateSelectedDraft(next => {
                    const item = next.browserTabs.find(candidate => candidate.id === tab.id)
                    if (item) item.profileSlotId = value
                }, { rerender: true })
            })
        ]),
        textArea({
            label: 'Tab notes',
            value: tab.notes,
            maxLength: PHONE_DRAFT_LIMITS.maxBrowserTabNotesLength,
            rows: 2,
            onInput: value => mutateSelectedDraft(next => {
                const item = next.browserTabs.find(candidate => candidate.id === tab.id)
                if (item) item.notes = value
            })
        }),
        createElement('div', { className: 'item-footer' }, [
            checkboxInput({
                label: 'Enabled',
                checked: tab.enabled !== false,
                onChange: value => mutateSelectedDraft(next => {
                    const item = next.browserTabs.find(candidate => candidate.id === tab.id)
                    if (item) item.enabled = value
                })
            }),
            button('Remove tab', 'btn danger small', () => {
                mutateSelectedDraft(next => {
                    next.browserTabs = next.browserTabs.filter(candidate => candidate.id !== tab.id)
                    next.browserTabs.forEach((candidate, index) => { candidate.order = index })
                }, { rerender: true, message: 'Removed browser tab.' })
            })
        ])
    ])
}

function renderAppsSection(draft) {
    return createElement('section', { className: 'panel' }, [
        createElement('div', { className: 'section-head' }, [
            createElement('h2', { text: 'Desired Desktop Apps' }),
            createElement('span', { text: `${draft.desiredApps.length}/${PHONE_DRAFT_LIMITS.maxDesiredApps}` })
        ]),
        createElement('p', {
            className: 'helper',
            text: 'Add app names only. These export as unresolved placeholders and cannot launch until resolved on desktop.'
        }),
        button('Add app placeholder', 'btn small', () => {
            mutateSelectedDraft(next => {
                if (next.desiredApps.length >= PHONE_DRAFT_LIMITS.maxDesiredApps) throw new Error('Desired app limit reached.')
                next.desiredApps.push(createDesiredAppPlaceholder({ name: `App ${next.desiredApps.length + 1}` }))
            }, { rerender: true, message: 'Added desired app placeholder.' })
        }, draft.desiredApps.length >= PHONE_DRAFT_LIMITS.maxDesiredApps),
        createElement('div', { className: 'item-list' }, draft.desiredApps.map(app => renderDesiredAppItem(app)))
    ])
}

function renderDesiredAppItem(app) {
    return createElement('article', { className: 'item' }, [
        createElement('div', { className: 'grid two' }, [
            textInput({
                label: 'Name',
                value: app.name,
                maxLength: PHONE_DRAFT_LIMITS.maxDesiredAppNameLength,
                onInput: value => mutateSelectedDraft(next => {
                    const item = next.desiredApps.find(candidate => candidate.id === app.id)
                    if (item) item.name = value
                })
            }),
            textInput({
                label: 'Label',
                value: app.label,
                maxLength: PHONE_DRAFT_LIMITS.maxDesiredAppLabelLength,
                onInput: value => mutateSelectedDraft(next => {
                    const item = next.desiredApps.find(candidate => candidate.id === app.id)
                    if (item) item.label = value
                })
            })
        ]),
        textArea({
            label: 'Notes',
            value: app.notes,
            maxLength: PHONE_DRAFT_LIMITS.maxDesiredAppNotesLength,
            rows: 2,
            onInput: value => mutateSelectedDraft(next => {
                const item = next.desiredApps.find(candidate => candidate.id === app.id)
                if (item) item.notes = value
            })
        }),
        createElement('div', { className: 'item-footer' }, [
            checkboxInput({
                label: 'Enabled placeholder',
                checked: app.enabled !== false,
                onChange: value => mutateSelectedDraft(next => {
                    const item = next.desiredApps.find(candidate => candidate.id === app.id)
                    if (item) item.enabled = value
                })
            }),
            button('Remove app', 'btn danger small', () => {
                mutateSelectedDraft(next => {
                    next.desiredApps = next.desiredApps.filter(candidate => candidate.id !== app.id)
                }, { rerender: true, message: 'Removed desired app placeholder.' })
            })
        ])
    ])
}

function safeFileName(name) {
    const safe = String(name || 'wipesnap-draft')
        .trim()
        .replace(/[^A-Za-z0-9._-]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .slice(0, 80)
    return safe || 'wipesnap-draft'
}

function downloadJson(draft, json) {
    const blob = new Blob([json], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `${safeFileName(draft.name)}.wipesnap-draft.json`
    document.body.appendChild(link)
    link.click()
    link.remove()
    URL.revokeObjectURL(url)
}

function exportSelectedDraft({ download = true } = {}) {
    const draft = selectedDraft()
    if (!draft) return
    try {
        const json = exportCloudDraftJson(draft)
        lastExportJson = json
        statusMessage = 'Exported validated draft JSON.'
        errorMessage = ''
        if (download) downloadJson(draft, json)
    } catch (err) {
        errorMessage = err?.message || 'Draft cannot be exported.'
    }
    render()
}

function renderExportPanel(draft) {
    const validation = validateDraftForExport(draft)
    const message = validation.valid
        ? 'Ready to export. Phase 15 desktop validation should accept this JSON.'
        : validation.errors[0]
    return createElement('section', { className: `panel export-panel ${validation.valid ? '' : 'blocked'}` }, [
        createElement('div', { className: 'section-head' }, [
            createElement('h2', { text: 'Export' }),
            createElement('span', { text: validation.valid ? 'valid' : 'blocked' })
        ]),
        createElement('p', { className: 'helper', text: message }),
        createElement('div', { className: 'export-actions' }, [
            button('Export JSON', 'btn primary', () => exportSelectedDraft(), !validation.valid),
            button('Preview JSON', 'btn', () => exportSelectedDraft({ download: false }), !validation.valid)
        ]),
        createElement('textarea', {
            className: 'export-json',
            readonly: true,
            rows: 10,
            value: lastExportJson || ''
        })
    ])
}

function renderEmptyState() {
    return createElement('main', { className: 'empty-state' }, [
        createElement('h2', { text: 'No local drafts' }),
        createElement('p', { text: 'Create a draft to start planning tabs, account intentions, profile intentions, and app placeholders.' }),
        button('Create draft', 'btn primary', () => {
            commitState(createPhonePlannerState(), 'Created local draft.')
        })
    ])
}

function render() {
    root.textContent = ''
    const draft = selectedDraft()
    root.appendChild(renderHeader())
    root.appendChild(createElement('div', { id: 'status-line', className: 'status', text: errorMessage || statusMessage }))
    if (!draft) {
        root.appendChild(renderEmptyState())
        renderStatus()
        return
    }

    root.appendChild(createElement('main', { className: 'planner-grid' }, [
        renderDraftPicker(draft),
        renderDraftDetails(draft),
        renderProfileSection(draft),
        renderAccountSection(draft),
        renderTabsSection(draft),
        renderAppsSection(draft),
        renderExportPanel(draft)
    ]))
    renderStatus()
}

render()
