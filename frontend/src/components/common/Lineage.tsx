import type { RunLineage } from '@/types/api'
import { shortHash } from '@/utils/format'

/**
 * The §37 decision chain behind every number on screen: which batch scored
 * it, which CRI run contextualised it, which enrichment and explain runs
 * annotated it, and which alert run and policy put it in the queue.
 */
export function LineageChain({ run }: { run: RunLineage | null | undefined }) {
  if (!run) return null
  const steps: { k: string; v: string | null; title: string }[] = [
    { k: 'model', v: run.registry_version, title: `Served model ${run.model_version}` },
    { k: 'batch', v: run.batch_run_id, title: 'Chapter 8 batch that produced the stored anomaly scores' },
    { k: 'cri', v: run.cri_run_id, title: 'Chapter 9 CRI run' },
    { k: 'att&ck', v: run.mitre_run_id, title: 'Chapter 10 enrichment run' },
    { k: 'explain', v: run.explain_run_id, title: 'Chapter 11 explain run' },
    { k: 'alerts', v: run.alert_run_id, title: `Chapter 12 alert run, policy ${run.policy_version} (${run.policy_hash})` },
  ]
  return (
    <div className="flex flex-wrap items-center gap-y-1 border-t border-line px-3 py-2" aria-label="Run lineage">
      <span className="t-label mr-3">Lineage</span>
      {steps.map((s, i) => (
        <span key={s.k} className="flex items-center" title={s.title}>
          <span className="t-code-sm text-ink-faint">{s.k}</span>
          <span className="t-code-sm ml-1 text-ink-muted">{s.v ?? 'none'}</span>
          {i < steps.length - 1 && <span className="mx-2 text-ink-ghost">›</span>}
        </span>
      ))}
      <span className="t-code-sm ml-3 text-ink-ghost" title="Alert policy version and hash">
        {run.policy_version}#{shortHash(run.policy_hash)}
      </span>
    </div>
  )
}
