import { Tag } from '@/components/ui/Tag'

const TITLES: Record<string, string> = {
  band: 'Band trigger: the CRI reached HIGH or CRITICAL on a member day (alert policy, N39)',
  top_k: "Daily budget trigger: the day was in the served model's top-k for its date (N39, N56)",
}

export function TriggerTags({ triggers }: { triggers: string[] }) {
  if (!triggers.length) return <span className="t-code-sm text-ink-ghost">—</span>
  return (
    <span className="inline-flex gap-1">
      {triggers.map((t) => (
        <Tag key={t} tone={t === 'band' ? 'indigo' : 'cyan'} title={TITLES[t] ?? t}>
          {t === 'top_k' ? 'top-k' : t}
        </Tag>
      ))}
    </span>
  )
}
