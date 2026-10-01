import { useState } from 'react'
import { Icon } from '@/components/ui/Icon'
import { ErrorPanel } from '@/components/ui/States'
import { scoreDay } from '@/services/risk'
import type { FeatureVector, RiskRow, RiskScoreOut } from '@/types/api'
import { type ApiError, toApiError } from '@/utils/errors'
import { fmtAnomaly, fmtCri } from '@/utils/format'

/**
 * Reproduce a stored decision (§37, N64). The day's stored feature vector and
 * LDAP role go back through POST /risk/score: the served model, the
 * calibrated CRI engine and the ATT&CK rules run again, nothing is stored,
 * and the result is set beside the stored scores. Equal values show the
 * decision on screen is the one the pipeline made.
 */
export function ReproducePanel({ fv, risk }: { fv: FeatureVector; risk: RiskRow }) {
  const [state, setState] = useState<{ busy: boolean; out: RiskScoreOut | null; err: ApiError | null; ms: number | null }>(
    { busy: false, out: null, err: null, ms: null },
  )
  const run = async () => {
    setState({ busy: true, out: null, err: null, ms: null })
    const t0 = performance.now()
    try {
      const features = Object.fromEntries(fv.values.map((v) => [v.column, v.value]))
      const out = await scoreDay({ user_id: fv.user_id, date: fv.activity_date, features, role: risk.ldap_role, explain: false })
      setState({ busy: false, out, err: null, ms: performance.now() - t0 })
    } catch (e) {
      setState({ busy: false, out: null, err: toApiError(e), ms: null })
    }
  }

  const out = state.out
  const dA = out ? Math.abs(out.anomaly.anomaly_score - risk.anomaly_score) : null
  const cri = out?.risk?.cri_score
  const dC = out && typeof cri === 'number' ? Math.abs(cri - risk.cri_score) : null
  const okA = dA !== null && dA <= 1e-9
  const okC = dC !== null && dC <= 1e-6

  return (
    <div className="flex flex-col gap-3 p-5">
      <p className="t-body-sm text-ink-muted">
        Send this day&apos;s stored feature vector back through the served model and the CRI engine. The result is computed on
        demand and never stored.
      </p>
      <button className="btn btn-secondary self-start" onClick={run} disabled={state.busy}>
        <Icon name="play" size={12} /> {state.busy ? 'Re-scoring…' : 'Re-score this day'}
      </button>
      {state.err && <ErrorPanel error={state.err} compact />}
      {out && (
        <div className="flex flex-col gap-2">
          <table className="w-full">
            <thead>
              <tr className="t-label text-left">
                <th className="pb-1 font-semibold" />
                <th className="pb-1 text-right font-semibold">Stored</th>
                <th className="pb-1 text-right font-semibold">Now</th>
                <th className="pb-1 text-right font-semibold">Diff</th>
              </tr>
            </thead>
            <tbody className="t-code-sm">
              <tr className="border-t border-row-line">
                <td className="py-1.5 text-ink-muted">anomaly</td>
                <td className="py-1.5 text-right text-ink">{fmtAnomaly(risk.anomaly_score, 6)}</td>
                <td className="py-1.5 text-right text-ink">{fmtAnomaly(out.anomaly.anomaly_score, 6)}</td>
                <td className={`py-1.5 text-right ${okA ? 'text-sev-low-text' : 'text-sev-critical-text'}`}>{dA === 0 ? '0' : dA?.toExponential(1)}</td>
              </tr>
              <tr className="border-t border-row-line">
                <td className="py-1.5 text-ink-muted">CRI</td>
                <td className="py-1.5 text-right text-ink">{fmtCri(risk.cri_score, 4)}</td>
                <td className="py-1.5 text-right text-ink">{typeof cri === 'number' ? fmtCri(cri, 4) : '—'}</td>
                <td className={`py-1.5 text-right ${okC ? 'text-sev-low-text' : 'text-sev-critical-text'}`}>{dC === null ? '—' : dC === 0 ? '0' : dC.toExponential(1)}</td>
              </tr>
              <tr className="border-t border-row-line">
                <td className="py-1.5 text-ink-muted">band</td>
                <td className="py-1.5 text-right text-ink">{risk.severity}</td>
                <td className="py-1.5 text-right text-ink">{out.risk?.severity ?? '—'}</td>
                <td className="py-1.5 text-right">{out.risk?.severity === risk.severity ? <span className="text-sev-low-text">same</span> : <span className="text-sev-critical-text">differs</span>}</td>
              </tr>
            </tbody>
          </table>
          <p className={`t-body-sm flex items-start gap-2 ${okA && okC ? 'text-sev-low-text' : 'text-sev-medium-text'}`}>
            <Icon name={okA && okC ? 'check' : 'warn'} size={14} className="mt-0.5 shrink-0" />
            {okA && okC
              ? 'The stored decision reproduces from its stored inputs.'
              : out.risk_unavailable_reason ?? 'The recomputed values differ from the stored ones. Check the served model and CRI calibration on the System page.'}
          </p>
          <p className="t-body-sm text-ink-faint">
            Band trigger now: {out.alert_trigger.by_band === null ? 'not evaluated' : out.alert_trigger.by_band ? 'yes' : 'no'}. Daily top-k is not
            evaluated for one day, because it ranks a whole day&apos;s population.
            {Object.keys(out.unavailable_components).length > 0 && ` Unavailable: ${Object.keys(out.unavailable_components).join(', ')}.`}
            {state.ms !== null && <span className="t-code-sm ml-1 text-ink-ghost">{Math.round(state.ms)} ms, persisted: {String(out.persisted)}</span>}
          </p>
        </div>
      )}
    </div>
  )
}
