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
  anomaly: { label: 'Anomaly score rarity', short: 'Anomaly', color: '#00FF9C', side: 'model' },
  historical_deviation: { label: "Deviation from the user's own last 30 days", short: 'Own history', color: '#B266FF', side: 'context' },
  peer_deviation: { label: 'Deviation from department peers', short: 'Peers', color: '#CC99FF', side: 'context' },
  user_context: { label: 'User context (privileged role list)', short: 'Role', color: '#E2CCFF', side: 'context' },
  asset_criticality: { label: 'Asset criticality', short: 'Asset', color: '#737373', side: 'context' },
  mitre_context: { label: 'ATT&CK context', short: 'ATT&CK', color: '#FF2BD6', side: 'attack' },
}

export const PROVENANCE = {
  model: { color: '#00FF9C', name: 'Served model' },
  context: { color: '#B266FF', name: 'CRI context' },
  attack: { color: '#FF2BD6', name: 'ATT&CK' },
} as const
