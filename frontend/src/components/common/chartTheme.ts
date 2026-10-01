/** Recharts styling shared by every chart: hairline grid, mono ticks, no decoration. */
export const AXIS = {
  stroke: '#2A3649',
  tick: { fill: '#94A3B8', fontSize: 11, fontFamily: "'JetBrains Mono Variable', monospace" },
  tickLine: false as const,
}
export const GRID = { stroke: '#1A2230', strokeDasharray: '0', vertical: false }
export const TOOLTIP_STYLE = {
  contentStyle: {
    background: '#252E42',
    border: '1px solid #3B475D',
    borderRadius: 4,
    boxShadow: '0px 4px 12px rgba(0,0,0,0.6)',
    fontSize: 12,
    padding: '6px 8px',
  },
  labelStyle: { color: '#F1F5F9', fontFamily: "'JetBrains Mono Variable', monospace", marginBottom: 4 },
  itemStyle: { color: '#E2E8F0', padding: 0 },
  cursor: { fill: 'rgba(56, 189, 248, 0.06)', stroke: '#3B475D' },
}
