import type { ReactNode } from 'react'

/** A titled section. `meta` is a one-line plain description under the title. */
export function Panel({ title, meta, actions, children, className = '', bodyClassName = '', id }: {
  title?: ReactNode
  meta?: ReactNode
  actions?: ReactNode
  children: ReactNode
  className?: string
  bodyClassName?: string
  id?: string
}) {
  return (
    <section id={id} className={`panel flex min-w-0 flex-col ${className}`}>
      {(title || actions || meta) && (
        <header className="panel-head">
          <div className="flex min-w-0 flex-col gap-0.5">
            {title && <h2 className="text-[15px] font-semibold leading-6 text-ink-strong">{title}</h2>}
            {meta && <span className="text-[13px] leading-5 text-ink-faint">{meta}</span>}
          </div>
          {actions && <div className="ml-auto flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={`min-w-0 flex-1 ${bodyClassName}`}>{children}</div>
    </section>
  )
}
