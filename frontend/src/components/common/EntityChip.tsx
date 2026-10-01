import { Link } from 'react-router'
import { Icon } from '@/components/ui/Icon'

/** Identity chip (DESIGN.md): icon + mono id, pivots to the user's investigation. */
export function UserChip({ userId, to = true }: { userId: string; to?: boolean }) {
  const body = (
    <>
      <Icon name="user" size={12} className="text-ink-faint group-hover:text-indigo" />
      <span className="font-mono text-[13px] uppercase text-ink">{userId}</span>
    </>
  )
  const cls = 'group inline-flex h-7 items-center gap-1.5 rounded-md border border-line-strong bg-chip px-2'
  if (!to) return <span className={cls}>{body}</span>
  return (
    <Link to={`/users/${encodeURIComponent(userId)}`} className={`${cls} hover:border-indigo/60`} onClick={(e) => e.stopPropagation()} title={`Open investigation of ${userId}`}>
      {body}
    </Link>
  )
}

export function DeviceChip({ deviceId }: { deviceId: string | null }) {
  if (!deviceId) return <span className="t-code-sm text-ink-ghost">—</span>
  return (
    <span className="inline-flex h-7 items-center rounded-md border border-line-strong bg-chip px-1.5 font-mono text-[12px] uppercase text-ink-muted">
      {deviceId}
    </span>
  )
}
