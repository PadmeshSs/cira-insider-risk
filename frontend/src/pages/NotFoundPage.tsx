import { Link } from 'react-router'

export default function NotFoundPage() {
  return (
    <div className="panel flex flex-col gap-2 p-6">
      <h1 className="t-headline-lg text-ink-strong">No such view</h1>
      <p className="t-body-sm text-ink-muted">The address does not match a view of the console.</p>
      <Link to="/" className="link t-body-sm">Go to the overview</Link>
    </div>
  )
}
