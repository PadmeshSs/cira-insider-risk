import { COMPONENT_META, CRI_COMPONENTS } from '@/constants/cri'
import { SEV_STYLE } from '@/constants/severity'
import { useBands } from '@/hooks/useBands'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import type { RiskRow, StoredAnomalyScore } from '@/types/api'
import { columnLabel, fmtAnomaly, fmtCri } from '@/utils/format'

/**
 * Score anatomy of one user-day. Two instruments, never one axis:
 *   left   the served model's anomaly score, a ranking score in [0, 1] (N20)
 *   right  the CRI, 0-100, and the points each component adds to it
 * Points sum to the CRI exactly (points_c = 100 * w_c * component_c), so the
 * composition bar is the score itself. A component without a value is listed
 * as excluded, never filled in (N35).
 */
export function ScoreAnatomy({ risk, anomaly }: { risk: RiskRow; anomaly?: StoredAnomalyScore | null }) {
  const sev = SEV_STYLE[risk.severity]
  const { bands: BANDS } = useBands()
  const rows = CRI_COMPONENTS.map((c) => ({
    c,
    meta: COMPONENT_META[c],
    value: risk.components[c] ?? null,
    points: risk.points[c] ?? null,
    missing: risk.missing_components.includes(c) || risk.components[c] === null || risk.components[c] === undefined,
  }))
  const sum = rows.reduce((a, r) => a + (r.points ?? 0), 0)
  const drift = Math.abs(sum - risk.cri_score)

  return (
    <div className="grid grid-cols-1 gap-px bg-line lg:grid-cols-[minmax(240px,0.8fr)_2fr]">
      {/* Model instrument */}
      <div className="flex flex-col gap-3 bg-l1 p-6">
        <div className="flex items-center gap-2">
          <span className="h-2.5 w-2.5 bg-prov-model" />
          <span className="t-label">Served model anomaly score</span>
        </div>
        <span className="t-metric text-ink-strong">{fmtAnomaly(risk.anomaly_score)}</span>
        <div className="relative h-1.5 bg-l2">
          <span className="absolute inset-y-0 left-0 bg-prov-model" style={{ width: `${risk.anomaly_score * 100}%` }} />
        </div>
        <div className="flex justify-between t-code-sm text-ink-ghost"><span>0</span><span>1</span></div>
        <p className="t-body-sm text-ink-muted">
          A ranking score from a class-weighted model. Higher means more unusual for the model; it is not the probability that
          this user is an insider.
        </p>
        {anomaly && (
          <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 border-t border-line pt-3">
            <dt className="t-code-sm text-ink-faint">model</dt>
            <dd className="t-code-sm text-ink">{anomaly.model_name} {anomaly.registry_version}</dd>
            <dt className="t-code-sm text-ink-faint">margin</dt>
            <dd className="t-code-sm text-ink" title="Raw log-odds margin; anomaly score = sigmoid(margin)">{anomaly.raw_score.toFixed(4)} log-odds</dd>
            <dt className="t-code-sm text-ink-faint">batch</dt>
            <dd className="t-code-sm truncate text-ink-muted" title={anomaly.batch_run_id}>{anomaly.batch_run_id}</dd>
          </dl>
        )}
      </div>

      {/* CRI instrument */}
      <div className="flex flex-col gap-3 bg-l1 p-6">
        <div className="flex items-center gap-2">
          <span className="h-2.5 w-2.5" style={{ background: sev.base }} />
          <span className="t-label">Contextual risk (CRI)</span>
          <span className="ml-auto"><SeverityBadge severity={risk.severity} value={risk.cri_score} /></span>
        </div>
        <span className="t-metric" style={{ color: sev.text }}>
          {fmtCri(risk.cri_score)}
          <span className="t-code ml-1.5 text-ink-faint">/ 100</span>
        </span>

        {/* Composition: each component's points laid end to end on the 0-100 scale */}
        <div className="flex flex-col gap-1">
          <div className="relative h-5 bg-l2" role="img" aria-label={`CRI ${fmtCri(risk.cri_score)} made of ${rows.filter((r) => (r.points ?? 0) > 0).map((r) => `${r.meta.short} ${fmtCri(r.points)}`).join(', ')}`}>
            <div className="absolute inset-0 flex">
              {rows.map((r) =>
                (r.points ?? 0) > 0 ? (
                  <span
                    key={r.c}
                    className="h-full border-r border-l1"
                    style={{ width: `${r.points}%`, background: r.meta.color }}
                    title={`${r.meta.label}: ${fmtCri(r.points, 2)} points`}
                  />
                ) : null,
              )}
            </div>
            {BANDS.slice(1).map((b) => (
              <span key={b.from} className="absolute -bottom-1 -top-1 w-px bg-ink-faint/60" style={{ left: `${b.from}%` }} />
            ))}
          </div>
          <div className="relative h-4">
            {BANDS.map((b) => (
              <span key={b.severity} className="absolute font-mono text-[10px]" style={{ left: `${b.from}%`, width: `${b.to - b.from}%`, color: SEV_STYLE[b.severity].text, paddingLeft: 3 }}>
                {b.severity}
              </span>
            ))}
          </div>
        </div>

        <table className="w-full">
          <thead>
            <tr className="t-label text-left">
              <th className="pb-1 font-semibold">Component</th>
              <th className="pb-1 pl-4 text-right font-semibold" title="Component value on its rarity scale, 0 to 1">Value</th>
              <th className="pb-1 pl-4 text-right font-semibold">Points</th>
              <th className="w-[38%] pb-1 pl-4 font-semibold">Detail</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.c} className="border-t border-row-line">
                <td className="py-1.5">
                  <span className="flex items-center gap-2">
                    <span className="h-2 w-2 shrink-0" style={{ background: r.meta.color }} />
                    <span className="text-[13px] text-ink">{r.meta.label}</span>
                  </span>
                </td>
                <td className="t-code py-1.5 text-right text-ink-muted">{r.value === null ? '—' : r.value.toFixed(3)}</td>
                <td className="t-code py-1.5 text-right text-ink-strong">{r.missing ? '—' : fmtCri(r.points, 2)}</td>
                <td className="t-body-sm py-1.5 pl-4 text-ink-faint">
                  {r.missing ? (
                    <span className="text-sev-medium-text">no value on this day; excluded, not imputed</span>
                  ) : r.c === 'historical_deviation' && risk.historical_top_feature ? (
                    <>largest rise: <span className="text-ink-muted">{columnLabel(risk.historical_top_feature)}</span></>
                  ) : r.c === 'peer_deviation' && risk.peer_top_feature ? (
                    <>largest above peers: <span className="text-ink-muted">{columnLabel(risk.peer_top_feature)}</span></>
                  ) : r.c === 'user_context' ? (
                    <>role <span className="text-ink-muted">{risk.ldap_role ?? 'unknown'}</span></>
                  ) : r.c === 'anomaly' ? (
                    'the model score on the calibrated rarity scale'
                  ) : (r.points ?? 0) === 0 ? (
                    'adds nothing on this day'
                  ) : null}
                </td>
              </tr>
            ))}
            <tr className="border-t border-line-strong">
              <td className="py-1.5 text-[13px] font-semibold text-ink">CRI</td>
              <td />
              <td className="t-code py-1.5 text-right font-semibold" style={{ color: sev.text }}>{fmtCri(risk.cri_score, 2)}</td>
              <td className="t-body-sm py-1.5 pl-4 text-ink-faint">
                {drift < 0.01 ? 'points add up to the stored CRI' : `points sum to ${fmtCri(sum, 2)}, stored CRI differs by ${drift.toFixed(3)}`}
              </td>
            </tr>
          </tbody>
        </table>
        <span className="t-code-sm text-ink-ghost">
          {risk.cri_version} · variant {risk.cri_variant} · calibration {risk.calibration_id} · config {risk.cri_config_hash.slice(0, 8)}
        </span>
      </div>
    </div>
  )
}
