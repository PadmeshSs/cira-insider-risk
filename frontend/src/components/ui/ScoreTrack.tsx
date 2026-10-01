/**
 * The served model's anomaly score on its own [0, 1] track, in the model's
 * provenance colour. Deliberately a different instrument from the CRI gauge:
 * the two numbers are never merged or compared on one axis (N34), and this
 * one is a ranking score, not a probability (N20).
 */
export function ScoreTrack({ value, width = 96, height = 6, digits = 5, showValue = true, max = 1 }: {
  value: number | null | undefined
  width?: number | string
  height?: number
  digits?: number
  showValue?: boolean
  max?: number
}) {
  if (value === null || value === undefined) return <span className="t-code-sm text-ink-faint">—</span>
  const pct = Math.max(0, Math.min(100, (100 * value) / max))
  return (
    <span className="inline-flex items-center gap-2" title={`Anomaly score ${value.toFixed(6)} (ranking score, not a probability)`}>
      <span className="relative inline-block bg-l2" style={{ width, height }}>
        <span className="absolute inset-y-0 left-0 bg-prov-model" style={{ width: `${pct}%` }} />
      </span>
      {showValue && <span className="t-code text-ink-strong">{value.toFixed(digits)}</span>}
    </span>
  )
}
