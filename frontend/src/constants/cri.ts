/**
 * CRI components (app/cri/config.py COMPONENTS). Points per component sum to
 * the CRI exactly (points_c = 100 * w_c * component_c), so the composition bar
 * is the score, not an approximation of it. The anomaly component is the
 * served model's score put on a rarity scale; the others are context (N34).
 */
export const CRI_COMPONENTS = [
  'anomaly',
  'historical_deviation',
  'peer_deviation',
  'user_context',
  'asset_criticality',
  'mitre_context',
] as const

export type CriComponent = (typeof CRI_COMPONENTS)[number]

export const COMPONENT_META: Record<string, { label: string; short: string; color: string; side: 'model' | 'context' | 'attack' }> = {
  anomaly: { label: 'Anomaly score rarity', short: 'Anomaly', color: '#38BDF8', side: 'model' },
  historical_deviation: { label: "Deviation from the user's own last 30 days", short: 'Own history', color: '#818CF8', side: 'context' },
  peer_deviation: { label: 'Deviation from department peers', short: 'Peers', color: '#A5B4FC', side: 'context' },
  user_context: { label: 'User context (privileged role list)', short: 'Role', color: '#C7D2FE', side: 'context' },
  asset_criticality: { label: 'Asset criticality', short: 'Asset', color: '#64748B', side: 'context' },
  mitre_context: { label: 'ATT&CK context', short: 'ATT&CK', color: '#E879F9', side: 'attack' },
}

export const PROVENANCE = {
  model: { color: '#38BDF8', name: 'Served model' },
  context: { color: '#818CF8', name: 'CRI context' },
  attack: { color: '#E879F9', name: 'ATT&CK' },
} as const
