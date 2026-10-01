import type { CertEvent } from '@/types/api'

const n = (v: unknown) => (typeof v === 'number' ? v : v === null || v === undefined ? null : Number(v))
const list = (v: unknown) => (typeof v === 'string' && v.trim() ? v.split(';').map((x) => x.trim()).filter(Boolean) : [])

/**
 * One line per CERT event, from what r4.2 records for its domain and nothing
 * more (N9): logon/device activity, file extension, email recipients, size
 * and attachment count, and the web host visited.
 */
export function eventSummary(e: CertEvent): string {
  const d = e.details ?? {}
  switch (e.source_type) {
    case 'logon':
      return String(d.activity ?? e.event_type.replace('logon_', '')) === 'logoff' ? 'Logoff' : 'Logon'
    case 'device':
      return String(d.activity ?? '').toLowerCase() === 'disconnect' ? 'Removable device disconnected' : 'Removable device connected'
    case 'file':
      return `File copied to removable media${d.file_extension ? ` (${String(d.file_extension)})` : ''}`
    case 'email': {
      const to = list(d.to).length + list(d.cc).length + list(d.bcc).length
      const att = n(d.attachments)
      const size = n(d.size)
      return `Email to ${to} recipient${to === 1 ? '' : 's'}${att ? `, ${att} attachment${att === 1 ? '' : 's'}` : ''}${size !== null ? `, ${Math.round(size / 1024)} KB message` : ''}`
    }
    case 'http':
      return `Visited ${String(d.host ?? 'a web host')}`
    default:
      return e.event_type
  }
}

export function isSecondary(e: CertEvent): boolean {
  const a = String(e.details?.activity ?? '').toLowerCase()
  return (e.source_type === 'logon' && a === 'logoff') || (e.source_type === 'device' && a === 'disconnect')
}
