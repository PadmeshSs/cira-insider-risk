import type { SourceType } from '@/types/api'

/** CERT r4.2 domains the API stores (app/services/lineage.py SOURCE_TYPES). */
export const SOURCE_TYPES: SourceType[] = ['logon', 'device', 'file', 'email', 'http']

export const SOURCE_META: Record<SourceType, { label: string; color: string; what: string }> = {
  logon: { label: 'Logon', color: '#38BDF8', what: 'logon.csv: logon and logoff on a PC' },
  device: { label: 'USB device', color: '#F59E0B', what: 'device.csv: removable device connect and disconnect' },
  file: { label: 'File copy', color: '#A5B4FC', what: 'file.csv: file copied to removable media (name and extension only)' },
  email: { label: 'Email', color: '#5EEAD4', what: 'email.csv: recipients, size and attachment count' },
  http: { label: 'Web', color: '#94A3B8', what: 'http.csv: URL visited (CERT records the visit, not what was sent)' },
}

/** Off-hours as the Chapter 5 features define them: outside 07:00-19:00. */
export const WORK_START_H = 7
export const WORK_END_H = 19
