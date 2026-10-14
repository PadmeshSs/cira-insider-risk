/** Recharts styling shared by every chart: hairline grid, mono ticks, no decoration. */
export const AXIS = {
  stroke: '#333333',
  tick: { fill: '#A3A3A3', fontSize: 11, fontFamily: "'JetBrains Mono Variable', monospace" },
  tickLine: false as const,
}
export const GRID = { stroke: '#1A1A1A', strokeDasharray: '2 4', vertical: false }
export const TOOLTIP_STYLE = {
  contentStyle: {
    background: '#0A0A0A',
    border: '1px solid #4A4A4A',
    borderRadius: 0,
    boxShadow: '0px 6px 18px rgba(0,0,0,0.8)',
    fontSize: 12,
    padding: '6px 8px',
  },
  labelStyle: { color: '#FFFFFF', fontFamily: "'JetBrains Mono Variable', monospace", marginBottom: 4 },
  itemStyle: { color: '#E6E6E6', padding: 0 },
  cursor: { fill: 'rgba(0, 255, 156, 0.05)', stroke: '#4A4A4A' },
}
