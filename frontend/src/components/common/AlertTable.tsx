import { useNavigate } from 'react-router'
import { Hint } from '@/components/ui/Hint'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { Tag } from '@/components/ui/Tag'
import type { AlertSummary } from '@/types/api'
import { fmtAnomaly, fmtDay, fmtDayRange, sentenceLabel } from '@/utils/format'
import { UserChip } from './EntityChip'

const MODEL_SCORE_HELP =
  "The served model's anomaly score, 0 to 1. The queue is ordered by it. It ranks how unusual a day is; it is not the probability that someone is an insider."
const SEVERITY_HELP = 'Highest contextual risk (CRI, 0 to 100) reached on any day of the alert. Shown as context; it does not change the order.'

/**
 * The review queue, one alert per row, in the policy's order (N55). Each row
 * answers who, how severe, how unusual, why, and when. Repeats folded into an
 * open alert are always shown and never called resolved (N57, N60).
 */
export function AlertTable({ items, rankOffset = 0, compact = false, showUser = true, showRank = true }: {
  items: AlertSummary[]
  rankOffset?: number
  compact?: boolean
  showUser?: boolean
  showRank?: boolean
}) {
  const navigate = useNavigate()
  const open = (id: number) => navigate(`/alerts/${id}`)
  return (
    <div className="overflow-x-auto">
      <table className="grid-table">
        <thead>
          <tr>
            {showRank && <th className="w-12">Rank</th>}
            <th>Alert</th>
            {showUser && <th>User</th>}
            <th><Hint title={SEVERITY_HELP}><span className="cursor-help border-b border-dotted border-ink-ghost">Severity</span></Hint></th>
            <th><Hint title={MODEL_SCORE_HELP}><span className="cursor-help border-b border-dotted border-ink-ghost">Model score</span></Hint></th>
            {!compact && <th>Main reason</th>}
            <th>When</th>
            {!compact && <th>Repeats</th>}
          </tr>
        </thead>
        <tbody>
          {items.map((a, i) => (
            <tr key={a.id} className="is-link" onClick={() => open(a.id)} tabIndex={0} onKeyDown={(e) => e.key === 'Enter' && open(a.id)}>
              {showRank && <td className="text-[14px] text-ink-faint">{a.status === 'open' ? rankOffset + i + 1 : '–'}</td>}
              <td>
                <div className="flex items-center gap-2">
                  <span className="text-[14px] font-semibold text-ink-strong">#{a.id}</span>
                  {a.status !== 'open' && (
                    <Tag tone="warn" mono={false} title={`A repeat of alert #${a.duplicate_of_id}, kept out of the queue. Not resolved.`}>
                      Repeat of #{a.duplicate_of_id}
                    </Tag>
                  )}
                  {a.in_sample && (
                    <Tag tone="danger" mono={false} title="The model was trained on this user's labels, so the score is not a detection (N31).">
                      In training data
                    </Tag>
                  )}
                </div>
              </td>
              {showUser && <td><UserChip userId={a.user_id} /></td>}
              <td><SeverityBadge severity={a.max_severity} value={a.max_cri_score} /></td>
              <td>
                <div className="flex items-center gap-3" title={`${a.ordering} ${fmtAnomaly(a.queue_score, 6)}`}>
                  <span className="t-code w-12 text-[14px] text-ink-strong">{a.queue_score.toFixed(3)}</span>
                  <span className="relative h-1.5 w-16 rounded-full bg-l2">
                    <span className="absolute inset-y-0 left-0 rounded-full bg-prov-model" style={{ width: `${a.queue_score * 100}%` }} />
                  </span>
                </div>
              </td>
              {!compact && (
                <td className="max-w-[280px]">
                  <div className="flex flex-col gap-0.5">
                    <span className="truncate text-[14px] text-ink" title={a.top_feature ?? undefined}>{sentenceLabel(a.top_feature)}</span>
                    <span className="text-[12px] text-ink-faint">
                      {a.techniques.length
                        ? `${a.techniques.length} ATT&CK technique${a.techniques.length === 1 ? '' : 's'}: ${a.techniques.slice(0, 2).join(', ')}${a.techniques.length > 2 ? '…' : ''}`
                        : 'No ATT&CK technique'}
                    </span>
                  </div>
                </td>
              )}
              <td>
                <div className="flex flex-col gap-0.5" title={`${a.first_date} to ${a.last_date}, peak ${a.peak_date}`}>
                  <span className="text-[14px] text-ink">{fmtDayRange(a.first_date, a.last_date)}</span>
                  <span className="text-[12px] text-ink-faint">
                    {a.n_days} day{a.n_days === 1 ? '' : 's'}{a.n_days > 1 ? `, peak ${fmtDay(a.peak_date, false)}` : ''}
                  </span>
                </div>
              </td>
              {!compact && (
                <td>
                  {a.suppressed && a.suppressed.count > 0 ? (
                    <div className="flex flex-col gap-0.5" title="Later alerts with the same pattern inside the cooldown. Kept, not resolved.">
                      <span className="text-[14px] text-sev-medium-text">+{a.suppressed.count} more</span>
                      <span className="text-[12px] text-ink-faint">{fmtDayRange(a.suppressed.first_date, a.suppressed.last_date)}</span>
                    </div>
                  ) : (
                    <span className="text-[14px] text-ink-ghost">None</span>
                  )}
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
