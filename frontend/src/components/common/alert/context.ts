import { useOutletContext, useSearchParams } from 'react-router'
import type { AlertDetail, AlertMember } from '@/types/api'

export interface AlertOutlet {
  detail: AlertDetail
}

export function useAlertOutlet() {
  return useOutletContext<AlertOutlet>()
}

/**
 * The member day under inspection, kept in the URL (?day=) so it survives the
 * move between Summary, Explainability and ATT&CK. Defaults to the peak day.
 */
export function useSelectedDay(members: AlertMember[]): [AlertMember | undefined, (day: string) => void] {
  const [sp, setSp] = useSearchParams()
  const want = sp.get('day')
  const sorted = [...members].sort((a, b) => a.activity_date.localeCompare(b.activity_date))
  const chosen = sorted.find((m) => m.activity_date === want) ?? sorted.find((m) => m.is_peak) ?? sorted[0]
  const select = (day: string) => {
    const next = new URLSearchParams(sp)
    next.set('day', day)
    setSp(next, { replace: true })
  }
  return [chosen, select]
}
