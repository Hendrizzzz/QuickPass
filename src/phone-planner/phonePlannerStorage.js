import {
    PHONE_PLANNER_STORAGE_VERSION,
    createPhonePlannerState,
    normalizeStoredPlannerState
} from './phonePlannerCore.js'

export const PHONE_PLANNER_STORAGE_KEY = 'wipesnap.phonePlanner.localDrafts.v1'

function getStorage(storage) {
    if (storage) return storage
    if (!globalThis.localStorage) {
        throw new Error('Phone planner local storage is not available.')
    }
    return globalThis.localStorage
}

export function loadPhonePlannerState({
    storage,
    storageKey = PHONE_PLANNER_STORAGE_KEY,
    now = Date.now,
    idFactory
} = {}) {
    const targetStorage = getStorage(storage)
    const raw = targetStorage.getItem(storageKey)
    if (!raw) return createPhonePlannerState({ now, idFactory })

    try {
        return normalizeStoredPlannerState(JSON.parse(raw), { now, idFactory })
    } catch (err) {
        const fallback = createPhonePlannerState({ now, idFactory })
        return {
            ...fallback,
            loadError: err?.message || 'Stored phone drafts could not be loaded.'
        }
    }
}

export function savePhonePlannerState(state, {
    storage,
    storageKey = PHONE_PLANNER_STORAGE_KEY,
    now = Date.now,
    idFactory,
    createIfEmpty = true
} = {}) {
    const targetStorage = getStorage(storage)
    const normalized = normalizeStoredPlannerState(state, { now, idFactory, createIfEmpty })
    targetStorage.setItem(storageKey, JSON.stringify({
        storageVersion: PHONE_PLANNER_STORAGE_VERSION,
        selectedDraftId: normalized.selectedDraftId,
        drafts: normalized.drafts,
        lastSavedAt: normalized.lastSavedAt
    }))
    return normalized
}

export function clearPhonePlannerState({
    storage,
    storageKey = PHONE_PLANNER_STORAGE_KEY
} = {}) {
    getStorage(storage).removeItem(storageKey)
}
