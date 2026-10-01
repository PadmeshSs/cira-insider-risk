import { SEV_STYLE, SEVERITIES } from '@/constants/severity'
import type { Severity } from '@/types/api'

const NAME: Record<Severity, string> = { CRITICAL: 'Critical', HIGH: 'High', MEDIUM: 'Medium', LOW: 'Low' }

/** Alerts per highest CRI band, one labelled row each, highest band first. */
export function SeverityMix({ counts }: { counts: Record<string, number> }) {
  const total = SEVERITIES.reduce((a, s) => a + (counts[s] ?? 0), 0)
  return (
    <ul className="flex flex-col gap-2">
      {[...SEVERITIES].reverse().map((s) => {
        const n = counts[s] ?? 0
        return (
          <li key={s} className="grid grid-cols-[64px_1fr_32px] items-center gap-3">
            <span className="flex items-center gap-2 text-[13px] text-ink">
              <span className="h-2 w-2 rounded-full" style={{ background: SEV_STYLE[s].base }} />
              {NAME[s]}
            </span>
            <span className="h-1.5 rounded-full bg-l2">
              <span className="block h-full rounded-full" style={{ width: total ? `${(100 * n) / total}%` : 0, background: SEV_STYLE[s].base }} />
            </span>
            <span className={`text-right text-[13px] font-medium ${n ? 'text-ink-strong' : 'text-ink-ghost'}`}>{n}</span>
          </li>
        )
      })}
    </ul>
  )
}
