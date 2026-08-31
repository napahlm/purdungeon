/** Platform-aware UI copy. The ⌘ glyph on a Windows machine is a lie. */
export const isMac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.userAgent)

/** Display label for the primary modifier key (search shortcut, etc.). */
export const modKeyLabel = isMac ? '⌘' : 'Ctrl'
