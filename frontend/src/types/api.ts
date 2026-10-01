/**
 * Response and request models of the Chapter 13 API (backend/app/schemas/*.py).
 * Field names and optionality follow the Pydantic models one to one; dates
 * arrive as ISO strings. The anomaly score and the CRI stay two fields
 * everywhere (N34) and neither is a probability (N20).
 */

export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
export type ISODate = string
export type ISODateTime = string

// ---- common.py --------------------------------------------------------------
export interface PageInfo {
  total: number
  limit: number
  offset: number
  max_limit: number
}

export interface RunLineage {
  alert_run_id: string
  policy_version: string
  policy_hash: string
  model_version: string
  registry_version: string
  batch_run_id: string
  cri_run_id: string
  explain_run_id: string
  mitre_run_id: string | null
}

export interface QueueInfo {
  ordered_by: string
  policy_version: string
  policy_hash: string
  sort: string
  context: string
}

export interface Coverage {
  persisted_days: number
  first_date: ISODate | null
  last_date: ISODate | null
  note: string
}

export interface ApiErrorBody {
  detail: { code: string; message: string; component?: string } | string | unknown
}

// ---- auth.py ----------------------------------------------------------------
export interface Token {
  access_token: string
  token_type: string
  expires_at: ISODateTime
}

export interface Analyst {
  id: number
  username: string
  email: string
  role: string
  department: string | null
  is_active: boolean
  created_at: ISODateTime | null
  token_expires_at: ISODateTime | null
}

// ---- alerts.py --------------------------------------------------------------
export interface SuppressedSummary {
  count: number
  first_date: ISODate | null
  last_date: ISODate | null
}

export interface AlertSummary {
  id: number
  alert_key: string
  user_id: string
  status: 'open' | 'suppressed' | string
  duplicate_of_id: number | null
  first_date: ISODate
  last_date: ISODate
  peak_date: ISODate
  n_days: number
  queue_score: number
  ordering: string
  peak_anomaly_score: number
  peak_cri_score: number
  max_cri_score: number
  max_severity: Severity
  triggers: string[]
  techniques: string[]
  top_feature: string | null
  model_split: string
  in_sample: boolean
  explanation_status: string
  suppressed: SuppressedSummary | null
}

export interface AlertCounts {
  open: number
  suppressed: number
}

export interface AlertQueue {
  items: AlertSummary[]
  page: PageInfo
  counts: AlertCounts
  queue: QueueInfo
  run: RunLineage
}

export interface AlertMember {
  id: number
  user_id: string
  activity_date: ISODate
  is_peak: boolean
  by_band: boolean
  by_top_k: boolean
  anomaly_score: number
  cri_score: number
  severity: Severity
  model_split: string
  in_sample: boolean
  explanation_status: string
  explanation_reason: string | null
  risk_score_id: number
  anomaly_score_id: number
  feature_vector_id: number
}

export interface AlertDetail {
  alert: AlertSummary
  members: AlertMember[]
  duplicate_of: AlertSummary | null
  suppressed_alerts: AlertSummary[]
  queue: QueueInfo
  run: RunLineage
}

// ---- anomaly.py -------------------------------------------------------------
export interface StoredAnomalyScore {
  id: number
  user_id: string
  activity_date: ISODate
  anomaly_score: number
  raw_score: number
  model_name: string
  model_version: string
  registry_version: string
  role: string
  model_split: string
  in_sample: boolean
  batch_run_id: string
  feature_vector_id: number
  model_version_id: number
}

// ---- events.py --------------------------------------------------------------
export type SourceType = 'logon' | 'device' | 'file' | 'email' | 'http'

export interface CertEvent {
  id: number
  source_type: SourceType
  event_type: string
  event_id: string
  user_id: string
  device_id: string | null
  event_time: ISODateTime
  activity_date: ISODate
  details: Record<string, unknown> | null
  feature_vector_id: number | null
  source_path: string
}

export interface EventPage {
  items: CertEvent[]
  page: PageInfo
  note: string
}

// ---- explanations.py --------------------------------------------------------
export interface ModelFactorSource {
  kind: 'model'
  method: string
  model_name: string
  model_version: string
  registry_version: string
  feature: string
  contribution: number
  feature_value: number | null
}

export interface ModelFactor {
  feature: string
  label: string
  domain: string
  value: number | null
  value_text: string
  contribution: number
  effect_text: string
  calendar?: boolean
  text: string
  rank?: number
  source: ModelFactorSource
}

export interface ContextFactor {
  component: string
  points: number
  text: string
  source: {
    kind: 'cri'
    cri_run_id?: string | null
    calibration_id?: string | null
    cri_config_hash?: string | null
    component: string
    points: number
    detail_column: string | null
  }
}

export interface AttackMatch {
  rule_id: string
  technique_id: string
  technique_name: string | null
  tactic: string | null
  evidence: 'observed' | 'indicated' | string | null
  trigger_column: string
  trigger_value: number | null
  strength: number | null
  text: string
  source: Record<string, unknown>
}

export interface AttackContext {
  status: 'mapped' | 'unmapped' | 'not_evaluated' | 'not_joined' | string
  mitre_context?: number | null
  matches: AttackMatch[]
  unmapped_behaviours: { behaviour: string; technique: null; reason: string | null }[]
  text: string[]
}

export interface ExplanationHeadline {
  severity?: Severity | null
  cri_score?: number | null
  anomaly_score?: number | null
  model_name?: string | null
  model_version?: string | null
  registry_version?: string | null
}

export interface Corroboration {
  method?: string
  top5_overlap?: number | null
  deletion_top_beats_random?: boolean | number | null
  note?: string
}

export interface MemberExplanation {
  member_id: number
  alert_id: number
  user_id: string
  activity_date: ISODate
  status: 'complete' | 'model_explanation_deferred' | string
  model_unavailable_reason: string | null
  headline: ExplanationHeadline
  sections: {
    model: ModelFactor[]
    model_lowering: ModelFactor[]
    cri: ContextFactor[]
    mitre: AttackContext | null
  }
  unavailable: Record<string, string>
  corroboration: Corroboration | null
  text: string
  reason_rows: Record<string, number>
  explain_run_id: string
}

export interface AlertExplanations {
  alert_id: number
  members: MemberExplanation[]
  run: RunLineage
}

// ---- features.py ------------------------------------------------------------
export interface FeatureValue {
  column: string
  value: number | null
  value_text: string
  label: string
  domain: string
  kind: string
  described: boolean
  static: boolean
  model_input: boolean
}

export interface FeatureVector {
  id: number
  user_id: string
  activity_date: ISODate
  profile: string
  features_fingerprint: string
  pipeline_version: string | null
  source_path: string
  loaded_for: string
  model_inputs: number
  values: FeatureValue[]
}

// ---- investigations.py ------------------------------------------------------
export interface Subject {
  user_id: string
  model_split: string
  in_sample: boolean
  persisted_days: number
  first_date: ISODate
  last_date: ISODate
  open_alerts: number
  suppressed_alerts: number
  max_queue_score: number | null
  max_severity: Severity | null
  in_demo_sample: boolean
  ldap_role: string | null
}

export interface SubjectPage {
  items: Subject[]
  page: PageInfo
  demo_window: Record<string, unknown> | null
  run: RunLineage
}

export interface Investigation {
  subject: Subject
  alerts: AlertSummary[]
  coverage: Coverage
  run: RunLineage
}

// ---- mitre.py ---------------------------------------------------------------
export interface Mapping {
  id: number
  user_id: string
  activity_date: ISODate
  status: 'mapped' | 'unmapped' | string
  technique_id: string | null
  technique_name: string | null
  tactic: string | null
  rule_id: string | null
  evidence: string | null
  trigger_column: string | null
  trigger_value: number | null
  strength: number | null
  mitre_context: number | null
  unmapped_behaviours: string[] | null
  ruleset_version: string
  ruleset_hash: string
  attack_version: string
  mitre_run_id: string
}

export interface MitreDay {
  activity_date: ISODate
  status: 'mapped' | 'unmapped' | 'not_evaluated' | string
  mappings: Mapping[]
}

export interface TechniqueCount {
  technique_id: string
  technique_name: string | null
  tactic: string | null
  days: number
}

export interface AlertMitre {
  alert_id: number
  days: MitreDay[]
  techniques: TechniqueCount[]
  note: string
  run: RunLineage
}

export interface MitreRule {
  rule_id: string
  pattern: string
  trigger_column: string
  evidence: string
  reasoning: string
  not_observable: string
}

export interface Technique {
  technique_id: string
  name: string
  full_name: string
  tactics: string[]
  is_subtechnique: boolean
  parent_id: string | null
  short_description: string
  url: string
  attack_version: string
  rules: MitreRule[]
  note: string
}

// ---- models.py --------------------------------------------------------------
export interface RegisteredModel {
  id: number
  model_name: string
  registry_version: string
  model_version: string
  run_id: string | null
  profile: string | null
  trained_at: string | null
  split_mode: string | null
  n_input_columns: number | null
  files: Record<string, unknown> | null
  created_at: ISODateTime | null
}

export interface ServedModelDescription {
  model_name?: string
  registry_version?: string
  model_version?: string
  run_id?: string | null
  profile?: string | null
  trained_at?: string | null
  split_mode?: string | null
  n_input_columns?: number
  static_inputs?: string[]
  device?: string
  role?: string
  use?: string
  [k: string]: unknown
}

export interface ModelsOut {
  status: string
  served: ServedModelDescription | null
  serving_source: string | null
  decision_rule: string | null
  reason: string | null
  shadow: ServedModelDescription[]
  score_convention: string | null
  in_database: RegisteredModel[]
}

// ---- risk.py ----------------------------------------------------------------
export interface RiskRow {
  risk_score_id: number
  anomaly_score_id: number
  user_id: string
  activity_date: ISODate
  anomaly_score: number
  cri_score: number
  severity: Severity
  components: Record<string, number | null>
  points: Record<string, number | null>
  missing_components: string[]
  historical_top_feature: string | null
  peer_top_feature: string | null
  ldap_role: string | null
  model_split: string
  in_sample: boolean
  model_version: string
  cri_version: string
  cri_config_hash: string
  cri_variant: string
  calibration_id: string
  cri_run_id: string
  mitre_run_id: string | null
  alert_ids: number[]
}

export interface HistoryBucket {
  start: ISODate
  end: ISODate
  days: number
  max_cri_score: number
  mean_cri_score: number
  max_anomaly_score: number
  mean_anomaly_score: number
  max_severity: Severity
  alert_member_days: number
}

export interface RiskHistory {
  user_id: string
  bucket: 'day' | 'week'
  coverage: Coverage
  buckets: HistoryBucket[]
  run: RunLineage
}

export interface RiskyUser {
  user_id: string
  open_alerts: number
  suppressed_alerts: number
  max_queue_score: number
  max_severity: Severity
  model_split: string
  in_sample: boolean
}

export interface Overview {
  counts: Record<string, number>
  open_by_severity: Record<string, number>
  open_by_split: Record<string, number>
  open_never_above_low: number
  top_features: { feature: string; open_alerts: number }[]
  open_led_by_usb_disconnect_count: number
  new_open_alerts: { start: ISODate; end: ISODate; count: number }[]
  top_users: RiskyUser[]
  queue: QueueInfo
  run: RunLineage
}

export interface RiskScoreRequest {
  user_id: string
  date: ISODate
  features: Record<string, number | null>
  role?: string | null
  explain?: boolean
}

export interface AnomalyScoreOut {
  anomaly_score: number
  raw_score: number
  model_name: string
  model_version: string
  registry_version: string
  role: 'served'
  scored_at: ISODateTime
  user_id: string | null
  date: ISODate | null
  persisted: boolean
}

export interface AlertTrigger {
  policy_version: string | null
  policy_hash: string | null
  by_band: boolean | null
  by_top_k: null
  eligible_for_top_k: boolean | null
  note: string
  reason: string | null
}

export interface RiskScoreOut {
  anomaly: AnomalyScoreOut
  risk: (Record<string, unknown> & { cri_score?: number; severity?: Severity }) | null
  risk_unavailable_reason: string | null
  unavailable_components: Record<string, string>
  mitre: Record<string, unknown> | null
  mitre_unavailable_reason: string | null
  alert_trigger: AlertTrigger
  explanation: Record<string, unknown> | null
  explanation_unavailable_reason: string | null
  persisted: boolean
}

// ---- /health ----------------------------------------------------------------
export interface ComponentBlock {
  status: string
  reason?: string | null
  [k: string]: unknown
}

export interface RouteReadiness {
  ready: boolean
  reason: string | null
  alert_run_id?: string | null
}

export interface Health {
  status: 'healthy' | 'degraded' | string
  service: string
  anomaly_model: ComponentBlock & { served?: ServedModelDescription | null }
  cri: ComponentBlock
  mitre: ComponentBlock
  explainability: ComponentBlock
  alerts: ComponentBlock
  database: ComponentBlock
  auth: ComponentBlock & { scheme?: string }
  routes: {
    auth: RouteReadiness
    alerts_risk_investigations: RouteReadiness
    anomaly_score: RouteReadiness
    risk_score: RouteReadiness
    mitre_techniques: RouteReadiness
  }
}
