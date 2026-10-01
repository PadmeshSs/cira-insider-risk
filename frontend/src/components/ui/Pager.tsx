import type { PageInfo } from '@/types/api'
import { Icon } from './Icon'

/** Offset pagination against the API's cap (N66). Never asks for "all". */
export function Pager({ page, onOffset }: { page: PageInfo | undefined; onOffset: (o: number) => void }) {
  if (!page) return null
  const from = page.total === 0 ? 0 : page.offset + 1
  const to = Math.min(page.offset + page.limit, page.total)
  return (
    <div className="flex items-center gap-3 border-t border-line px-3 py-2">
      <span className="t-code-sm text-ink-muted">
        {from}–{to} of {page.total}
      </span>
      <span className="t-body-sm text-ink-faint">page size {page.limit}, server cap {page.max_limit}</span>
      <div className="ml-auto flex gap-1">
        <button className="btn btn-secondary !h-7 !px-2" disabled={page.offset === 0} onClick={() => onOffset(Math.max(0, page.offset - page.limit))} aria-label="Previous page">
          <Icon name="chevronLeft" size={14} />
        </button>
        <button className="btn btn-secondary !h-7 !px-2" disabled={to >= page.total} onClick={() => onOffset(page.offset + page.limit)} aria-label="Next page">
          <Icon name="chevronRight" size={14} />
        </button>
      </div>
    </div>
  )
}
