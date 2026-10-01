import type { ReactNode } from 'react'

export function PageHeader({ title, sub, actions, crumbs }: { title: ReactNode; sub?: ReactNode; actions?: ReactNode; crumbs?: ReactNode }) {
  return (
    <header className="flex flex-wrap items-end gap-x-8 gap-y-4 pb-2">
      <div className="flex min-w-0 flex-col gap-2">
        {crumbs && <div className="flex items-center gap-1.5 text-[13px] text-ink-faint">{crumbs}</div>}
        <h1 className="t-headline-xl text-ink-strong">{title}</h1>
        {sub && <div className="max-w-[78ch] text-[14px] leading-6 text-ink-muted">{sub}</div>}
      </div>
      {actions && <div className="ml-auto flex items-center gap-3">{actions}</div>}
    </header>
  )
}
