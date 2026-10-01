import { useMemo } from 'react'
import { AlertTable } from '@/components/common/AlertTable'
import { FeatureVectorPanel } from '@/components/common/alert/FeatureVectorPanel'
import { MemberDaysStrip } from '@/components/common/alert/MemberDaysStrip'
import { ReproducePanel } from '@/components/common/alert/ReproducePanel'
import { ScoreAnatomy } from '@/components/common/alert/ScoreAnatomy'
import { useAlertOutlet, useSelectedDay } from '@/components/common/alert/context'
import { FeatureName } from '@/components/common/FeatureName'
import { Panel } from '@/components/ui/Panel'
import { ErrorPanel, SkeletonBlock, SkeletonRows } from '@/components/ui/States'
import { Tag } from '@/components/ui/Tag'
import { useApi } from '@/hooks/useApi'
import { storedAnomaly } from '@/services/anomaly'
import { alertExplanations } from '@/services/explanations'
import { featureVector } from '@/services/features'
import { riskDay } from '@/services/risk'
import { fmtDay, weekday } from '@/utils/format'

/** §27 "How risky is it?": the member days, the score anatomy of one day, its inputs, and a re-score check. */
export default function AlertSummaryPage() {
  const { detail } = useAlertOutlet()
  const [member, select] = useSelectedDay(detail.members)
  const user = detail.alert.user_id
  const day = member?.activity_date ?? detail.alert.peak_date

  const risk = useApi(`risk:${user}:${day}`, (s) => riskDay(user, day, s))
  const anomaly = useApi(`anomaly:${user}:${day}`, (s) => storedAnomaly(user, day, s))
  const fv = useApi(`features:${user}:${day}`, (s) => featureVector(user, day, s))
  const expl = useApi(`explain:${detail.alert.id}`, (s) => alertExplanations(detail.alert.id, s))

  const highlight = useMemo(() => {
    const m = new Map<string, number>()
    const e = expl.data?.members.find((x) => x.activity_date === day)
    for (const f of [...(e?.sections.model ?? []), ...(e?.sections.model_lowering ?? [])]) m.set(f.feature, f.contribution)
    return m
  }, [expl.data, day])

  const a = detail.alert
  return (
    <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
      <div className="flex min-w-0 flex-col gap-6 xl:col-span-8">
        <Panel title="Days in this alert" meta={`${detail.members.length} day${detail.members.length === 1 ? '' : 's'}. Pick one to see how its scores were made.`}>
          <MemberDaysStrip members={detail.members} selected={day} onSelect={select} />
        </Panel>

        <Panel
          title={<>How the scores were made · {fmtDay(day)}, {weekday(day)}</>}
          meta={member?.is_peak ? 'The peak day of this alert' : 'A day inside this alert'}
        >
          {risk.error ? <ErrorPanel error={risk.error} onRetry={risk.reload} /> : risk.data ? <ScoreAnatomy risk={risk.data} anomaly={anomaly.data} /> : <SkeletonBlock height={300} />}
        </Panel>

        <Panel title="Activity measured that day" meta="The stored inputs. Highlighted rows are the ones the explanation names.">
          {fv.error ? <ErrorPanel error={fv.error} onRetry={fv.reload} /> : fv.data ? <FeatureVectorPanel fv={fv.data} highlight={highlight} /> : <SkeletonRows rows={10} />}
        </Panel>
      </div>

      <div className="flex min-w-0 flex-col gap-6 xl:col-span-4">
        <Panel title="About this alert">
          <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-3 p-5">
            <dt className="text-[13px] text-ink-faint">Ordered by</dt>
            <dd className="text-[14px] text-ink">Model score <span className="t-code-sm text-ink-faint">({detail.queue.ordered_by})</span></dd>
            <dt className="text-[13px] text-ink-faint">Peak day</dt>
            <dd className="text-[14px] text-ink">{fmtDay(a.peak_date)}, {weekday(a.peak_date)}</dd>
            <dt className="text-[13px] text-ink-faint">Top model factor</dt>
            <dd><FeatureName column={a.top_feature} /></dd>
            <dt className="text-[13px] text-ink-faint">ATT&amp;CK</dt>
            <dd className="flex flex-wrap gap-1">
              {a.techniques.length ? a.techniques.map((t) => <Tag key={t} tone="attack">{t}</Tag>) : <span className="t-body-sm text-ink-muted">no technique on any member day</span>}
            </dd>
            <dt className="text-[13px] text-ink-faint">Explanation</dt>
            <dd className={`text-[14px] ${a.explanation_status === 'complete' ? 'text-ink' : 'text-sev-medium-text'}`}>{a.explanation_status === 'complete' ? 'Complete' : 'Model explanation pending'}</dd>
            <dt className="text-[13px] text-ink-faint">Model split</dt>
            <dd className={`text-[14px] ${a.in_sample ? 'text-sev-critical-text' : 'text-ink'}`}>{a.in_sample ? 'Training data: the score is not a detection' : `${a.model_split.charAt(0).toUpperCase()}${a.model_split.slice(1)} set (not seen in training)`}</dd>
          </dl>
        </Panel>

        <Panel title="Check the decision" meta="Recompute this day from its stored inputs">
          {fv.data && risk.data ? <ReproducePanel fv={fv.data} risk={risk.data} /> : <SkeletonRows rows={3} />}
        </Panel>

        {detail.suppressed_alerts.length > 0 && (
          <Panel id="suppressed" title="Repeats of this alert" meta="Kept out of the queue, not resolved">
            <p className="t-body-sm border-b border-line p-5 text-ink-muted">
              These alerts repeat this alert&apos;s pattern inside the cooldown. The activity they cover continued after this alert
              opened.
            </p>
            <AlertTable items={detail.suppressed_alerts} compact showUser={false} showRank={false} />
          </Panel>
        )}
      </div>
    </div>
  )
}
