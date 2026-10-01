import { useEffect } from 'react'
import { useHealth } from '@/store/health'

/** Poll /health while the shell is mounted. 30 s keeps the status bar honest without load. */
export function useHealthPolling(intervalMs = 30_000) {
  const refresh = useHealth((s) => s.refresh)
  useEffect(() => {
    void refresh()
    const t = window.setInterval(() => void refresh(), intervalMs)
    return () => window.clearInterval(t)
  }, [refresh, intervalMs])
}
