import { NavLink } from 'react-router'
import { Icon, type IconName } from '@/components/ui/Icon'
import { useAuth } from '@/store/auth'

const GROUPS: { title: string; items: { to: string; icon: IconName; label: string; hint: string; end?: boolean }[] }[] = [
  {
    title: 'Investigate',
    items: [
      { to: '/', icon: 'overview', label: 'Overview', hint: 'Who is risky right now', end: true },
      { to: '/alerts', icon: 'alerts', label: 'Alerts', hint: 'The review queue' },
      { to: '/users', icon: 'users', label: 'Users', hint: 'Monitored people' },
    ],
  },
  {
    title: 'Platform',
    items: [{ to: '/system', icon: 'system', label: 'System status', hint: 'Models, data and readiness' }],
  },
]

/** Labelled navigation: every destination says what it is, not just an icon. */
export function Sidebar() {
  const analyst = useAuth((s) => s.analyst)
  const signOut = useAuth((s) => s.signOut)
  return (
    <nav className="flex w-[248px] shrink-0 flex-col border-r border-line bg-l1" aria-label="Main">
      <div className="flex h-16 items-center gap-3 border-b border-line px-5">
        <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-cyan/10">
          <svg width="20" height="20" viewBox="0 0 32 32" aria-hidden="true">
            <path d="M8 22h4v-6H8zM14 22h4V10h-4zM20 22h4v-9h-4z" fill="#38BDF8" />
            <path d="M7 25h18" stroke="#EF4444" strokeWidth="2" />
          </svg>
        </span>
        <div className="flex flex-col leading-tight">
          <span className="text-[15px] font-semibold text-ink-strong">CIRA</span>
          <span className="text-[12px] text-ink-faint">Insider risk console</span>
        </div>
      </div>

      <div className="flex flex-1 flex-col gap-6 overflow-y-auto px-3 py-5">
        {GROUPS.map((g) => (
          <div key={g.title} className="flex flex-col gap-1">
            <span className="px-3 pb-1 text-[12px] font-medium text-ink-faint">{g.title}</span>
            {g.items.map((n) => (
              <NavLink
                key={n.to}
                to={n.to}
                end={n.end}
                className={({ isActive }) =>
                  `group relative flex items-center gap-3 rounded-lg px-3 py-2.5 transition-colors ${
                    isActive ? 'bg-l2 text-ink-strong' : 'text-ink-muted hover:bg-l2/60 hover:text-ink'
                  }`
                }
              >
                {({ isActive }) => (
                  <>
                    {isActive && <span className="absolute inset-y-2 left-0 w-[3px] rounded-r bg-cyan" aria-hidden="true" />}
                    <Icon name={n.icon} size={18} className={isActive ? 'text-cyan' : 'text-ink-faint group-hover:text-ink-muted'} />
                    <span className="flex flex-col leading-tight">
                      <span className="text-[14px] font-medium">{n.label}</span>
                      <span className="text-[12px] text-ink-faint">{n.hint}</span>
                    </span>
                  </>
                )}
              </NavLink>
            ))}
          </div>
        ))}
      </div>

      <div className="border-t border-line p-3">
        <div className="flex items-center gap-3 rounded-lg px-2 py-2">
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-indigo/15 text-[13px] font-semibold uppercase text-indigo">
            {analyst?.username.slice(0, 2) ?? '··'}
          </span>
          <div className="flex min-w-0 flex-1 flex-col leading-tight">
            <span className="truncate text-[14px] font-medium text-ink">{analyst?.username ?? 'Analyst'}</span>
            <span className="truncate text-[12px] text-ink-faint">{analyst?.role ?? 'signed in'}</span>
          </div>
          <button className="btn btn-ghost !px-2" onClick={() => signOut(null)} aria-label="Sign out" title="Sign out">
            <Icon name="logout" size={18} />
          </button>
        </div>
      </div>
    </nav>
  )
}
