const WEEKDAY = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']

/** Anomaly score: a ranking score in [0, 1], shown to 5 places like the stored explanation text. */
export const fmtAnomaly = (v: number | null | undefined, digits = 5) =>
  v === null || v === undefined || Number.isNaN(v) ? '—' : v.toFixed(digits)

/** CRI: 0-100, one decimal. */
export const fmtCri = (v: number | null | undefined, digits = 1) =>
  v === null || v === undefined || Number.isNaN(v) ? '—' : v.toFixed(digits)

export const fmtInt = (v: number | null | undefined) =>
  v === null || v === undefined ? '—' : new Intl.NumberFormat('en-US').format(v)

export const fmtSigned = (v: number | null | undefined, digits = 2) =>
  v === null || v === undefined ? '—' : `${v >= 0 ? '+' : ''}${v.toFixed(digits)}`

/** Calendar date of a YYYY-MM-DD string, parsed as a date (no time zone shift). */
export function parseDay(d: string): Date {
  const [y, m, day] = d.slice(0, 10).split('-').map(Number)
  return new Date(Date.UTC(y, m - 1, day))
}

export const weekday = (d: string) => WEEKDAY[parseDay(d).getUTCDay()]
export const isWeekend = (d: string) => [0, 6].includes(parseDay(d).getUTCDay())

export function dayDiff(a: string, b: string): number {
  return Math.round((parseDay(b).getTime() - parseDay(a).getTime()) / 86_400_000)
}

export function addDays(d: string, n: number): string {
  const t = parseDay(d)
  t.setUTCDate(t.getUTCDate() + n)
  return t.toISOString().slice(0, 10)
}

export function fmtSpan(first: string | null | undefined, last: string | null | undefined): string {
  if (!first) return '—'
  if (!last || last === first) return first
  if (first.slice(0, 7) === last.slice(0, 7)) return `${first} → ${last.slice(8, 10)}`
  return `${first} → ${last}`
}

/**
 * Local clock time of a CERT event as the dataset recorded it. Read from the
 * ISO string itself so the browser's time zone never moves an event across
 * the off-hours boundary.
 */
export function clockOf(iso: string): { hh: number; mm: number; ss: number; text: string } {
  const m = /T(\d{2}):(\d{2}):(\d{2})/.exec(iso)
  if (!m) return { hh: 0, mm: 0, ss: 0, text: '—' }
  const [hh, mm, ss] = [Number(m[1]), Number(m[2]), Number(m[3])]
  return { hh, mm, ss, text: `${m[1]}:${m[2]}:${m[3]}` }
}

/** Human label of a Chapter 5 column when no description came with it. */
export const columnLabel = (col: string) => col.replace(/_/g, ' ')

export const shortHash = (h: string | null | undefined, n = 8) => (h ? h.slice(0, n) : '—')

export function relTime(ms: number | null): string {
  if (!ms) return 'never'
  const s = Math.round((Date.now() - ms) / 1000)
  if (s < 5) return 'just now'
  if (s < 60) return `${s}s ago`
  const m = Math.round(s / 60)
  return m < 60 ? `${m}m ago` : `${Math.round(m / 60)}h ago`
}

export function pct(n: number, total: number): string {
  if (!total) return '0%'
  return `${Math.round((100 * n) / total)}%`
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

/** "19 Jan 2010": easier to read in tables than ISO, which stays in tooltips and detail. */
export function fmtDay(d: string | null | undefined, withYear = true): string {
  if (!d) return '—'
  const t = parseDay(d)
  return `${t.getUTCDate()} ${MONTHS[t.getUTCMonth()]}${withYear ? ` ${t.getUTCFullYear()}` : ''}`
}

export function fmtDayRange(first: string | null | undefined, last: string | null | undefined): string {
  if (!first) return '—'
  if (!last || last === first) return fmtDay(first)
  const sameYear = first.slice(0, 4) === last.slice(0, 4)
  return `${fmtDay(first, !sameYear)} – ${fmtDay(last)}`
}

/** "last_auth_hour" -> "Last auth hour" when the API sends no described label. */
export function sentenceLabel(col: string | null | undefined): string {
  if (!col) return '—'
  const s = col.replace(/_/g, ' ')
  return s.charAt(0).toUpperCase() + s.slice(1)
}
