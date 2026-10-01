import { createBrowserRouter, RouterProvider } from 'react-router'
import { AppShell } from '@/components/layout/AppShell'
import { RequireAuth } from '@/components/layout/RequireAuth'
import { SkeletonRows } from '@/components/ui/States'
import LoginPage from '@/pages/LoginPage'

/** Route modules load on demand, so the login screen does not wait for the chart library. */
const page = (load: () => Promise<{ default: React.ComponentType }>) => async () => ({ Component: (await load()).default })

/**
 * Eight views of Bible Chapter 14, each answering one §27 question:
 *   Overview            who is risky?
 *   Alerts              what happened?
 *   Alert details       how risky is it?
 *   Explainability      why is it risky?
 *   ATT&CK context      what contextual evidence supports it?
 *   User investigation  what should the analyst investigate?
 *   Risk history        how has the user's risk moved over persisted days?
 *   Login               the signed-in analyst (N65)
 */
const router = createBrowserRouter([
  { path: '/login', element: <LoginPage /> },
  {
    element: <RequireAuth />,
    children: [
      {
        element: <AppShell />,
        hydrateFallbackElement: <SkeletonRows rows={8} />,
        children: [
          { index: true, lazy: page(() => import('@/pages/OverviewPage')) },
          { path: 'alerts', lazy: page(() => import('@/pages/AlertsPage')) },
          {
            path: 'alerts/:alertId',
            lazy: page(() => import('@/pages/AlertLayout')),
            children: [
              { index: true, lazy: page(() => import('@/pages/AlertSummaryPage')) },
              { path: 'explain', lazy: page(() => import('@/pages/ExplainabilityPage')) },
              { path: 'mitre', lazy: page(() => import('@/pages/MitreContextPage')) },
            ],
          },
          { path: 'users', lazy: page(() => import('@/pages/UsersPage')) },
          { path: 'users/:userId', lazy: page(() => import('@/pages/UserInvestigationPage')) },
          { path: 'users/:userId/history', lazy: page(() => import('@/pages/RiskHistoryPage')) },
          { path: 'system', lazy: page(() => import('@/pages/SystemPage')) },
          { path: '*', lazy: page(() => import('@/pages/NotFoundPage')) },
        ],
      },
    ],
  },
])

export default function App() {
  return <RouterProvider router={router} />
}
