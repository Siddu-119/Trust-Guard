export type NavTab =
  | "overview"
  | "users"
  | "keys"
  | "messages"
  | "devices"
  | "threats"
  | "audit"
  | "backups"
  | "settings";

export type Role = "Admin" | "Employee" | "Viewer";

export interface AuthUser {
  user_id: string;
  username: string;
  full_name: string;
  role: Role;
  device_id: string | null;
}

export interface DemoAccount {
  user_id: string;
  username: string;
  full_name: string;
  role: Role;
  status: string;
  devices: { device_id: string; device_name: string; status: string }[];
}

export interface ServiceNode {
  node_id: string;
  name: string;
  role: string;
  status: "ONLINE" | "OFFLINE";
  synced_key_version: number;
  last_sync_at: string;
  last_sync_latency_ms: number;
  revoked_devices_enforced: number;
  pending_revocations: number;
  revocation_records: {
    device_id: string;
    enforced: number;
    enforcement_ms: number | null;
    enforced_at: string | null;
    status: string;
  }[];
}

export interface DashboardOverview {
  metrics: {
    total_users: number;
    active_devices: number;
    revoked_devices: number;
    active_keys: number;
    suspicious_activities: number;
    delivered_messages: number;
    pending_rotations: number;
  };
  key_rotation_status: {
    state: string;
    pending_count: number;
    latest_rotation: KeyRotation | null;
    key_breakdown: { status: string; count: number }[];
  };
  charts: {
    access_activity: { service: string; allow_count: number; deny_count: number }[];
    security_events: { category: string; count: number }[];
  };
  recent_security_events: ThreatAlert[];
  recent_audit_events: AuditEvent[];
  service_nodes: ServiceNode[];
  pqc_suite: {
    pqc_available: boolean;
    kem: string;
    signature: string;
    symmetric: string;
  };
}

export interface UserRecord {
  user_id: string;
  username: string;
  full_name: string;
  role: Role;
  status: string;
  created_at: string;
  permissions: {
    perm_id: string;
    resource: string;
    action: string;
    allowed: number;
    granted_by: string;
    created_at: string;
  }[];
}

export interface AccessDecision {
  decision_id: string;
  user_id: string;
  username: string;
  role: string;
  device_id: string | null;
  source_service: string;
  destination_service: string;
  resource: string;
  action: string;
  decision: "ALLOW" | "DENY";
  reason: string;
  timestamp: string;
}

export interface CryptoKey {
  key_id: string;
  purpose: string;
  owner_id: string;
  algorithm: string;
  version: number;
  status: "PENDING" | "ACTIVE" | "RETIRED" | "EXPIRED_CUTOFF" | "REVOKED";
  public_key_b64: string;
  created_at: string;
  activated_at: string | null;
  retired_at: string | null;
  cutoff_at: string | null;
  revoked_at: string | null;
}

export interface KeyRotation {
  rotation_id: string;
  purpose: string;
  owner_id: string;
  old_key_id: string | null;
  new_key_id: string;
  old_version: number | null;
  new_version: number;
  state: "PENDING" | "COMMITTED" | "ROLLED_BACK";
  initiated_by: string;
  started_at: string;
  committed_at: string | null;
  recovered: number;
  notes: string | null;
}

export interface DeviceRecord {
  device_id: string;
  owner_id: string;
  owner_username: string;
  owner_name: string;
  device_name: string;
  device_type: string;
  status: "ACTIVE" | "REVOKED";
  registered_at: string;
  last_activity: string;
  revoked_at: string | null;
  revoked_by: string | null;
  revocation_reason: string | null;
  replaces_device_id: string | null;
  node_enforcement: {
    node_id: string;
    node_name?: string;
    name?: string;
    enforced: number;
    enforcement_ms: number | null;
    enforced_at: string | null;
    status: string;
  }[];
}

export interface SecureMessage {
  message_id: string;
  session_id: string;
  sender_id: string;
  sender_username: string;
  sender_device_id: string;
  recipient_id: string;
  recipient_username: string;
  signing_key_id: string;
  signing_key_version: number;
  kem_algorithm: string;
  sig_algorithm: string;
  delivery_status: string;
  forward_secret: boolean;
  created_at: string;
  ciphertext_preview: string;
  plaintext: string | null;
}

export interface MessagingSession {
  session_id: string;
  initiator_id: string;
  initiator_username?: string;
  initiator_device_id: string;
  peer_id: string;
  peer_username?: string;
  step_counter: number;
  state: string;
  created_at: string;
  last_resumed_at: string;
}

export interface DeliveryAttempt {
  attempt_id: string;
  message_id: string;
  session_id: string | null;
  sender_id: string | null;
  recipient_id: string | null;
  status: string;
  failure_reason: string | null;
  attempted_at: string;
}

export interface ThreatAlert {
  alert_id: string;
  user_identity: string;
  source_service: string;
  destination_service: string;
  event_time: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  reason: string;
  rule_triggered: string;
  detection_latency_ms: number;
  ordering_status?: string;
  related_events?: string[];
  acknowledged: number;
}

export interface DatasetEvalMetrics {
  dataset_path: string;
  total_events: number;
  benign_events: number;
  malicious_events: number;
  true_positives: number;
  false_positives: number;
  true_negatives: number;
  false_negatives: number;
  precision: number;
  recall: number;
  f1_score: number;
  median_alert_time_ms: number;
  false_alerts_per_1000_benign: number;
  rule_hits: Record<string, number>;
  category_breakdown: Record<string, { total: number; detected: number }>;
  evaluated_at: string;
}

export interface AuditEvent {
  seq: number;
  event_id: string;
  actor_id: string;
  action: string;
  resource: string;
  timestamp: string;
  result: string;
  metadata_json: string;
  previous_hash: string;
  current_hash: string;
}

export interface AuditVerification {
  valid: boolean;
  tampered: boolean;
  checked_events: number;
  broken_event_id: string | null;
  broken_seq: number | null;
  latest_hash?: string;
  reason: string;
}

export interface BackupRecord {
  backup_id: string;
  created_by: string;
  created_at: string;
  key_count: number;
  revoked_count: number;
  payload_sha256: string;
  status: string;
}
