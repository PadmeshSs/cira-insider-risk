import type { ReactNode } from 'react'

const TONES = {
  neutral: 'border-line-strong text-ink-muted bg-chip',
  accent: 'border-accent/50 text-accent bg-accent/10',
  violet: 'border-violet/50 text-violet bg-violet/10',
  attack: 'border-prov-attack/50 text-prov-attack bg-prov-attack/10',
  warn: 'border-sev-medium/60 text-sev-medium-text bg-sev-medium/10',
  danger: 'border-sev-critical/60 text-sev-critical-text bg-sev-critical/10',
} as const

export function Tag({ children, tone = 'neutral', title, mono = true }: {
  children: ReactNode
  tone?: keyof typeof TONES
  title?: string
  mono?: boolean
}) {
  return (
    <span
      title={title}
      className={`inline-flex h-6 items-center gap-1 border px-2 text-[12px] leading-none ${mono ? 'font-mono' : 'font-medium'} ${TONES[tone]}`}
    >
      {children}
    </span>
  )
}
