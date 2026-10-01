import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { describe, expect, it } from 'vitest'
import { eventSummary } from '@/components/common/investigation/eventText'
import { ScoreAnatomy } from '@/components/common/alert/ScoreAnatomy'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { bandsFrom } from '@/constants/severity'
import type { CertEvent, RiskRow } from '@/types/api'
import { clockOf, dayDiff, fmtSpan } from '@/utils/format'
import { toApiError } from '@/utils/errors'
import { AxiosError, AxiosHeaders } from 'axios'

describe('formatting', () => {
  it('reads the clock time from the recorded timestamp, not the browser zone', () => {
    expect(clockOf('2010-08-16T22:14:05+00:00').text).toBe('22:14:05')
    expect(clockOf('2010-08-16T06:59:00-04:00').hh).toBe(6)
  })
  it('counts calendar days between member days', () => {
    expect(dayDiff('2010-08-30', '2010-09-02')).toBe(3)
  })
  it('shortens a span inside one month', () => {
    expect(fmtSpan('2010-08-02', '2010-08-19')).toBe('2010-08-02 → 19')
  })
  it('draws band limits from the served CRI config, not fixed numbers', () => {
    expect(bandsFrom({ LOW: 24, MEDIUM: 49, HIGH: 74, CRITICAL: 100 }).map((b) => [b.from, b.to])).toEqual([[0, 25], [25, 50], [50, 75], [75, 100]])
    expect(bandsFrom({ LOW: 29, MEDIUM: 59, HIGH: 79, CRITICAL: 100 }).map((b) => b.from)).toEqual([0, 30, 60, 80])
  })
})

describe('API errors', () => {
  it('keeps the backend code, message and component', () => {
    const err = new AxiosError('x', '503', undefined, undefined, {
      status: 503, statusText: '', headers: {}, config: { headers: new AxiosHeaders() },
      data: { detail: { code: 'unavailable', message: 'no alert run is loaded', component: 'alerts' } },
    })
    const e = toApiError(err)
    expect([e.status, e.code, e.component, e.message]).toEqual([503, 'unavailable', 'alerts', 'no alert run is loaded'])
  })
})

describe('severity badge', () => {
  it('shows the explicit value so colour never carries meaning alone', () => {
    render(<SeverityBadge severity="HIGH" value={68.4} />)
    expect(screen.getByText('HIGH')).toBeInTheDocument()
    expect(screen.getByText('68')).toBeInTheDocument()
  })
})

describe('CERT event wording', () => {
  const base = { id: 1, event_id: 'x', user_id: 'ACM2278', device_id: 'pc-1', event_time: '2010-01-04T08:00:00', activity_date: '2010-01-04', feature_vector_id: 1, source_path: 'p' }
  it('never claims more than CERT records', () => {
    const http = { ...base, source_type: 'http', event_type: 'http_request', details: { host: 'wikileaks.org' } } as CertEvent
    expect(eventSummary(http)).toBe('Visited wikileaks.org')
    const usb = { ...base, source_type: 'device', event_type: 'device_disconnect', details: { activity: 'disconnect' } } as CertEvent
    expect(eventSummary(usb)).toBe('Removable device disconnected')
    for (const e of [http, usb]) expect(eventSummary(e)).not.toMatch(/upload|exfiltrat|bytes transferred/i)
  })
})

describe('score anatomy', () => {
  const risk: RiskRow = {
    risk_score_id: 1, anomaly_score_id: 1, user_id: 'ACM2278', activity_date: '2010-08-16',
    anomaly_score: 0.98, cri_score: 61.5, severity: 'HIGH',
    components: { anomaly: 0.9, historical_deviation: 0.5, peer_deviation: null, user_context: 0, asset_criticality: null, mitre_context: 0.3 },
    points: { anomaly: 54, historical_deviation: 4.5, peer_deviation: 0, user_context: 0, asset_criticality: 0, mitre_context: 3 },
    missing_components: ['peer_deviation', 'asset_criticality'], historical_top_feature: 'usb_connect_count', peer_top_feature: null,
    ldap_role: 'Salesman', model_split: 'test', in_sample: false, model_version: 'm', cri_version: 'c', cri_config_hash: 'abcdef0123',
    cri_variant: 'default', calibration_id: 'cal', cri_run_id: 'r', mitre_run_id: null, alert_ids: [1],
  }
  it('shows points that add up to the stored CRI and marks missing components as excluded', () => {
    render(<MemoryRouter><ScoreAnatomy risk={risk} /></MemoryRouter>)
    expect(screen.getByText('points add up to the stored CRI')).toBeInTheDocument()
    expect(screen.getAllByText('no value on this day; excluded, not imputed')).toHaveLength(2)
    expect(screen.queryByText(/probability of/i)).toBeNull()
  })
})
