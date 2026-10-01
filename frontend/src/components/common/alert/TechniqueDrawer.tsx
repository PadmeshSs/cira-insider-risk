import Drawer from '@mui/material/Drawer'
import { Icon } from '@/components/ui/Icon'
import { ErrorPanel, SkeletonRows } from '@/components/ui/States'
import { Tag } from '@/components/ui/Tag'
import { useApi } from '@/hooks/useApi'
import { technique } from '@/services/mitre'

/** One technique from the pinned ATT&CK table, with the CIRA rules that can map a user-day to it. */
export function TechniqueDrawer({ id, onClose }: { id: string | null; onClose: () => void }) {
  const t = useApi(id ? `technique:${id}` : null, (s) => technique(id as string, s))
  return (
    <Drawer anchor="right" open={Boolean(id)} onClose={onClose} slotProps={{ paper: { sx: { width: { xs: '100%', sm: 480 } } } }}>
      <div className="flex h-full flex-col">
        <header className="flex items-center gap-2 border-b border-line px-4 py-3">
          <span className="font-mono text-[15px] font-semibold text-prov-attack">{id}</span>
          <span className="t-body-sm text-ink-faint">ATT&amp;CK technique</span>
          <button className="btn btn-ghost ml-auto" onClick={onClose} aria-label="Close"><Icon name="x" size={14} /></button>
        </header>
        <div className="flex-1 overflow-y-auto">
          {t.error ? <ErrorPanel error={t.error} onRetry={t.reload} /> : !t.data ? <SkeletonRows rows={6} /> : (
            <div className="flex flex-col gap-4 p-6">
              <div className="flex flex-col gap-2">
                <h2 className="t-headline-lg text-ink-strong">{t.data.full_name || t.data.name}</h2>
                <div className="flex flex-wrap gap-1">
                  {t.data.tactics.map((x) => <Tag key={x}>{x}</Tag>)}
                  {t.data.is_subtechnique && <Tag>sub-technique of {t.data.parent_id}</Tag>}
                  <Tag>ATT&amp;CK {t.data.attack_version}</Tag>
                </div>
                <p className="t-body-sm max-w-[64ch] text-ink-muted">{t.data.short_description}</p>
                <a href={t.data.url} target="_blank" rel="noreferrer" className="t-body-sm link inline-flex items-center gap-1 self-start">
                  attack.mitre.org <Icon name="external" size={12} />
                </a>
              </div>
              <div className="rounded-sm border border-line bg-ground p-2.5">
                <p className="t-body-sm text-ink-muted">{t.data.note}</p>
              </div>
              <div className="flex flex-col gap-2">
                <span className="t-label">CIRA rules that map to it</span>
                {t.data.rules.length === 0 && <p className="t-body-sm text-ink-muted">No CIRA rule maps a user-day to this technique.</p>}
                {t.data.rules.map((r) => (
                  <div key={r.rule_id} className="flex flex-col gap-1.5 rounded-sm border border-line p-5">
                    <div className="flex items-center gap-2">
                      <span className="t-code text-ink-strong">{r.rule_id}</span>
                      <Tag tone={r.evidence === 'indicated' ? 'warn' : 'attack'}>{r.evidence}</Tag>
                      <span className="t-code-sm ml-auto text-ink-faint">{r.trigger_column}</span>
                    </div>
                    <p className="text-[13px] text-ink">{r.pattern}</p>
                    <p className="t-body-sm text-ink-muted"><span className="text-ink-faint">Why: </span>{r.reasoning}</p>
                    <p className="t-body-sm text-ink-muted"><span className="text-ink-faint">CERT cannot show: </span>{r.not_observable}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </Drawer>
  )
}
