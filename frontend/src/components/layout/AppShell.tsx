import { Outlet } from 'react-router'
import { useHealthPolling } from '@/hooks/useHealthPolling'
import { Sidebar } from './Sidebar'
import { TopBar } from './TopBar'

export function AppShell() {
  useHealthPolling()
  return (
    <div className="flex h-full">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar />
        <main className="min-h-0 flex-1 overflow-y-auto">
          <div className="mx-auto w-full max-w-[1480px] px-8 pb-16 pt-8">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  )
}
