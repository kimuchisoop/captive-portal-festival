CREATE TABLE IF NOT EXISTS meta (name VARCHAR(255) PRIMARY KEY, value VARCHAR(255) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS terms_documents (
 document_id VARCHAR(255) NOT NULL, language VARCHAR(255) NOT NULL, version VARCHAR(255) NOT NULL, sha256 VARCHAR(255) NOT NULL, body MEDIUMTEXT NOT NULL,
 PRIMARY KEY(document_id,language)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TRIGGER immutable_terms BEFORE UPDATE ON terms_documents FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='immutable terms';
CREATE TABLE IF NOT EXISTS admins (
 id VARCHAR(255) PRIMARY KEY, username VARCHAR(255) UNIQUE NOT NULL, password_hash MEDIUMTEXT NOT NULL,
 role VARCHAR(255) NOT NULL CHECK(role IN ('viewer','operator','records','settings')), enabled BIGINT NOT NULL DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS sessions (
 token_hash VARCHAR(255) PRIMARY KEY, kind VARCHAR(255) NOT NULL, owner_id VARCHAR(255) NOT NULL, csrf_hash VARCHAR(255) NOT NULL,
 expires_at BIGINT NOT NULL, created_at BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS login_limits (bucket VARCHAR(255) PRIMARY KEY, count BIGINT NOT NULL, expires_at BIGINT NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS launches (
 token_hash VARCHAR(255) PRIMARY KEY, connection_ref VARCHAR(255) NOT NULL, expires_at BIGINT NOT NULL,
 owner_id VARCHAR(255), context_id VARCHAR(255)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS contexts (
 id VARCHAR(255) PRIMARY KEY, owner_id VARCHAR(255) NOT NULL, connection_ref VARCHAR(255) NOT NULL, expires_at BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS consents (
 id VARCHAR(255) PRIMARY KEY, event_id VARCHAR(255) NOT NULL, service_window_id VARCHAR(255) NOT NULL,
 terms_document_id VARCHAR(255) NOT NULL, terms_version VARCHAR(255) NOT NULL, terms_sha256 VARCHAR(255) NOT NULL,
 policy_version VARCHAR(255) NOT NULL, accepted_at_utc VARCHAR(255) NOT NULL, language VARCHAR(255) NOT NULL,
 accepted BIGINT NOT NULL CHECK(accepted=1), consent_method VARCHAR(255) NOT NULL,
 connection_ref VARCHAR(255) NOT NULL, request_id VARCHAR(255) NOT NULL, delete_after BIGINT NOT NULL, seq BIGINT UNSIGNED NOT NULL AUTO_INCREMENT UNIQUE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TRIGGER immutable_consent BEFORE UPDATE ON consents FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='immutable consent';
CREATE TABLE IF NOT EXISTS grants (
 id VARCHAR(255) PRIMARY KEY, consent_id VARCHAR(255) NOT NULL,
 owner_id VARCHAR(255) NOT NULL, connection_ref VARCHAR(255) NOT NULL, authorization_status VARCHAR(255) NOT NULL,
 observation_state VARCHAR(255) NOT NULL, revocation_state VARCHAR(255) NOT NULL,
 authorized_at BIGINT, original_expires_at BIGINT, last_observed_at BIGINT,
 revoked_at BIGINT, delete_after BIGINT NOT NULL, row_version BIGINT NOT NULL DEFAULT 1, seq BIGINT UNSIGNED NOT NULL AUTO_INCREMENT UNIQUE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS operations (
 id VARCHAR(255) PRIMARY KEY, grant_id VARCHAR(255),
 action VARCHAR(255) NOT NULL, reason_code VARCHAR(255) NOT NULL, actor VARCHAR(255) NOT NULL, status VARCHAR(255) NOT NULL,
 attempts BIGINT NOT NULL DEFAULT 0, next_attempt BIGINT NOT NULL,
 last_error_code VARCHAR(255), correlation_id VARCHAR(255) NOT NULL, delete_after BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS idempotency (
 owner_id VARCHAR(255) NOT NULL, path VARCHAR(255) NOT NULL, request_key VARCHAR(255) NOT NULL,
 body_hash VARCHAR(255) NOT NULL, response MEDIUMTEXT NOT NULL, status BIGINT NOT NULL, expires_at BIGINT NOT NULL,
 PRIMARY KEY(owner_id,path,request_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS audit (
 id VARCHAR(255) PRIMARY KEY, actor VARCHAR(255) NOT NULL, action VARCHAR(255) NOT NULL, object_id VARCHAR(255),
 created_at BIGINT NOT NULL, delete_after BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS notifications (
 id VARCHAR(255) PRIMARY KEY, dedupe_key VARCHAR(255) UNIQUE NOT NULL, severity VARCHAR(255) NOT NULL,
 code VARCHAR(255) NOT NULL, message MEDIUMTEXT NOT NULL, state VARCHAR(255) NOT NULL,
 first_seen BIGINT NOT NULL, last_seen BIGINT NOT NULL, acknowledged_by VARCHAR(255), acknowledged_at BIGINT, generation BIGINT NOT NULL DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE INDEX consent_expiry ON consents(delete_after);
CREATE INDEX operation_due ON operations(status,next_attempt);
CREATE INDEX session_expiry ON sessions(expires_at);

ALTER TABLE grants ADD FOREIGN KEY(consent_id) REFERENCES consents(id) ON DELETE CASCADE;
ALTER TABLE operations ADD FOREIGN KEY(grant_id) REFERENCES grants(id) ON DELETE CASCADE;

CREATE TABLE IF NOT EXISTS notification_updates (
 id VARCHAR(36) PRIMARY KEY, notification_id VARCHAR(255) NOT NULL, generation BIGINT NOT NULL,
 actor VARCHAR(255) NOT NULL, assignee VARCHAR(255), status VARCHAR(32) NOT NULL,
 note VARCHAR(1000) NOT NULL, created_at BIGINT NOT NULL, seq BIGINT UNSIGNED NOT NULL AUTO_INCREMENT UNIQUE,
 FOREIGN KEY(notification_id) REFERENCES notifications(id), FOREIGN KEY(actor) REFERENCES admins(id),
 FOREIGN KEY(assignee) REFERENCES admins(id), CHECK(status IN ('open','in_progress','handled')),
 INDEX notification_history(notification_id,seq)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TRIGGER immutable_handover BEFORE UPDATE ON notification_updates FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='immutable handover';
CREATE TABLE IF NOT EXISTS terms_revisions (
 id VARCHAR(36) PRIMARY KEY, version VARCHAR(80) NOT NULL, policy_version VARCHAR(80) NOT NULL,
 ja MEDIUMTEXT NOT NULL, en MEDIUMTEXT NOT NULL, actor VARCHAR(255) NOT NULL, created_at BIGINT NOT NULL,
 seq BIGINT UNSIGNED NOT NULL AUTO_INCREMENT UNIQUE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TRIGGER immutable_revisions BEFORE UPDATE ON terms_revisions FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='immutable revision';
CREATE TABLE IF NOT EXISTS terms_publications (
 id VARCHAR(36) PRIMARY KEY, revision_id VARCHAR(36) NOT NULL, actor VARCHAR(255) NOT NULL, created_at BIGINT NOT NULL,
 seq BIGINT UNSIGNED NOT NULL AUTO_INCREMENT UNIQUE, FOREIGN KEY(revision_id) REFERENCES terms_revisions(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TRIGGER immutable_publications BEFORE UPDATE ON terms_publications FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='immutable publication';
CREATE TABLE IF NOT EXISTS mfa_settings (
 admin_id VARCHAR(255) PRIMARY KEY, secret_ciphertext MEDIUMTEXT NOT NULL, generation VARCHAR(36) NOT NULL,
 enabled BIGINT NOT NULL, needs_reset BIGINT NOT NULL DEFAULT 0, last_counter BIGINT NOT NULL,
 FOREIGN KEY(admin_id) REFERENCES admins(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS mfa_recovery (
 admin_id VARCHAR(255) NOT NULL, generation VARCHAR(36) NOT NULL, code_hash VARCHAR(64) NOT NULL,
 used_at BIGINT, PRIMARY KEY(admin_id,generation,code_hash), FOREIGN KEY(admin_id) REFERENCES admins(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS storage_samples (
 bucket BIGINT PRIMARY KEY, observed_at BIGINT NOT NULL, database_bytes BIGINT NOT NULL,
 backup_bytes BIGINT NOT NULL, application_free_bytes BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE IF NOT EXISTS backup_checks (
 id VARCHAR(36) PRIMARY KEY, filename VARCHAR(120) NOT NULL, stage VARCHAR(16) NOT NULL,
 status VARCHAR(16) NOT NULL, code VARCHAR(80) NOT NULL, ciphertext_sha256 VARCHAR(64),
 file_bytes BIGINT, file_mtime_ns BIGINT, actor VARCHAR(255) NOT NULL, checked_at BIGINT NOT NULL,
 seq BIGINT UNSIGNED NOT NULL AUTO_INCREMENT UNIQUE,
 CHECK(stage IN ('decrypt','restore')), CHECK(status IN ('passed','failed')),
 INDEX backup_check_history(filename,seq)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TRIGGER immutable_backup_checks BEFORE UPDATE ON backup_checks FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='immutable backup check';
CREATE TABLE IF NOT EXISTS support_exports (
 id VARCHAR(36) PRIMARY KEY, actor VARCHAR(255) NOT NULL, created_at BIGINT NOT NULL,
 sha256 VARCHAR(64) NOT NULL, bytes BIGINT NOT NULL,
 seq BIGINT UNSIGNED NOT NULL AUTO_INCREMENT UNIQUE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TRIGGER immutable_support_exports BEFORE UPDATE ON support_exports FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='immutable support export';
CREATE TABLE IF NOT EXISTS checklist_runs (
 id VARCHAR(36) PRIMARY KEY, event_day VARCHAR(10) NOT NULL, phase VARCHAR(16) NOT NULL,
 checklist_version BIGINT NOT NULL, actor VARCHAR(255) NOT NULL, created_at BIGINT NOT NULL,
 UNIQUE(event_day,phase), CHECK(phase IN ('before','during','after'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS checklist_entries (
 id VARCHAR(36) PRIMARY KEY, run_id VARCHAR(36) NOT NULL, item_id VARCHAR(60) NOT NULL,
 actor VARCHAR(255) NOT NULL, assignee VARCHAR(255), outcome VARCHAR(16) NOT NULL,
 note VARCHAR(1000) NOT NULL, checked_at BIGINT NOT NULL, seq BIGINT UNSIGNED NOT NULL AUTO_INCREMENT UNIQUE,
 FOREIGN KEY(run_id) REFERENCES checklist_runs(id), FOREIGN KEY(actor) REFERENCES admins(id),
 FOREIGN KEY(assignee) REFERENCES admins(id), CHECK(outcome IN ('pending','ok','problem','na')),
 INDEX checklist_history(run_id,item_id,seq)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TRIGGER immutable_checklist_entries BEFORE UPDATE ON checklist_entries FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='immutable checklist entry';


CREATE TABLE event_info_plans (
  id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  created_by VARCHAR(255) NOT NULL,
  created_at BIGINT NOT NULL,
  target_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  base_config_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  content_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  base_values_json JSON NOT NULL,
  values_json JSON NOT NULL,
  source_file_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  source_file VARCHAR(96) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_eip_source_file (source_file),
  FOREIGN KEY (created_by) REFERENCES admins (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  CHECK (created_at >= 0),
  CHECK (JSON_TYPE(values_json) = 'OBJECT' AND JSON_TYPE(base_values_json) = 'OBJECT'),
  KEY ix_eip_created (created_at,id),
  KEY ix_eip_creator (created_by,created_at,id),
  KEY ix_eip_base (base_config_sha256,id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE event_info_plan_events (
  id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  plan_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  plan_version BIGINT UNSIGNED NOT NULL,
  kind VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  state_after VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  actor_id VARCHAR(255) NOT NULL,
  created_at BIGINT NOT NULL,
  confirmed_content_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  review_valid_until BIGINT NULL,
  reason_code VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  note VARCHAR(500) NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_eipe_version (plan_id,plan_version),
  UNIQUE KEY uq_eipe_plan_id (plan_id,id),
  FOREIGN KEY (plan_id) REFERENCES event_info_plans (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  FOREIGN KEY (actor_id) REFERENCES admins (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  CHECK ((kind='created' AND state_after='saved') OR (kind='review_requested' AND state_after='review_pending') OR (kind='review_recorded' AND state_after='reviewed') OR (kind='withdrawn' AND state_after='withdrawn')),
  CHECK ((kind='review_recorded' AND confirmed_content_sha256 IS NOT NULL AND review_valid_until IS NOT NULL AND review_valid_until > created_at) OR (kind<>'review_recorded' AND confirmed_content_sha256 IS NULL AND review_valid_until IS NULL)),
  CHECK (plan_version >= 1 AND created_at >= 0),
  KEY ix_eipe_actor (actor_id,created_at,id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE event_info_apply_attempts (
  id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  plan_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  review_event_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  plan_version BIGINT UNSIGNED NOT NULL,
  requested_by VARCHAR(255) NOT NULL,
  created_at BIGINT NOT NULL,
  correlation_id VARCHAR(255) NOT NULL,
  content_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  before_config_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  expected_after_config_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  new_service_window_id VARCHAR(255) NULL,
  history_prefix VARCHAR(96) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  PRIMARY KEY (id),
  FOREIGN KEY (plan_id) REFERENCES event_info_plans (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  FOREIGN KEY (plan_id,review_event_id) REFERENCES event_info_plan_events (plan_id,id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  CHECK (plan_version >= 1 AND created_at >= 0),
  KEY ix_eia_plan (plan_id,created_at,id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE event_info_apply_observations (
  id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  attempt_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  observation_version BIGINT UNSIGNED NOT NULL,
  outcome VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  observed_config_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  evidence_code VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  actor VARCHAR(255) NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_eiao_version (attempt_id,observation_version),
  FOREIGN KEY (attempt_id) REFERENCES event_info_apply_attempts (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  CHECK (outcome IN ('file_written','not_written','conflict','unknown')),
  CHECK (observation_version >= 1 AND created_at >= 0),
  CHECK (outcome='unknown' OR observed_config_sha256 IS NOT NULL)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE consent_archive_exports (
  id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  owner_id VARCHAR(255) NOT NULL,
  filters_json JSON NOT NULL,
  filters_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  as_of BIGINT NOT NULL,
  created_at BIGINT NOT NULL,
  state VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  row_version BIGINT UNSIGNED NOT NULL,
  retry_of_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
  error_code VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  PRIMARY KEY (id),
  FOREIGN KEY (owner_id) REFERENCES admins (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  FOREIGN KEY (retry_of_id) REFERENCES consent_archive_exports (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  CHECK (state IN ('queued','preparing','ready','failed')),
  CHECK (row_version >= 1 AND as_of >= 0 AND created_at >= 0),
  CHECK ((state='failed' AND error_code IS NOT NULL) OR (state<>'failed' AND error_code IS NULL)),
  CHECK (JSON_TYPE(filters_json)='OBJECT'),
  KEY ix_cae_owner (owner_id,created_at,id),
  KEY ix_cae_owner_state (owner_id,state,id),
  KEY ix_cae_queue (state,created_at,id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE consent_archive_snapshots (
  id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  export_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  snapshot_started_at BIGINT NOT NULL,
  prepared_at BIGINT NULL,
  state VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  item_count BIGINT UNSIGNED NULL,
  rows_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  error_code VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_cas_export (export_id),
  FOREIGN KEY (export_id) REFERENCES consent_archive_exports (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  CHECK (state IN ('preparing','ready','failed')),
  CHECK (snapshot_started_at >= 0),
  CHECK ((state='preparing' AND prepared_at IS NULL AND item_count IS NULL AND rows_sha256 IS NULL AND error_code IS NULL) OR (state='ready' AND prepared_at IS NOT NULL AND item_count IS NOT NULL AND item_count<=100000 AND rows_sha256 IS NOT NULL AND error_code IS NULL) OR (state='failed' AND prepared_at IS NOT NULL AND item_count IS NULL AND rows_sha256 IS NULL AND error_code IS NOT NULL))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE consent_archive_items (
  snapshot_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  ordinal BIGINT UNSIGNED NOT NULL,
  consent_id VARCHAR(255) NOT NULL,
  source_seq BIGINT UNSIGNED NOT NULL,
  event_id VARCHAR(255) NOT NULL,
  terms_version VARCHAR(255) NOT NULL,
  terms_sha256 VARCHAR(255) NOT NULL,
  policy_version VARCHAR(255) NOT NULL,
  accepted_at_utc VARCHAR(255) NOT NULL,
  language VARCHAR(255) NOT NULL,
  delete_after BIGINT NOT NULL,
  deadline_scope VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  row_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  PRIMARY KEY (snapshot_id,ordinal),
  UNIQUE KEY uq_cai_consent (snapshot_id,consent_id),
  FOREIGN KEY (snapshot_id) REFERENCES consent_archive_snapshots (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  FOREIGN KEY (consent_id) REFERENCES consents (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  CHECK (ordinal >= 1),
  CHECK (deadline_scope IN ('within_processing_deadline','processing_deadline_elapsed')),
  KEY ix_cai_consent (consent_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE consent_archive_events (
  id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  export_id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  kind VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  actor_type VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  actor_id VARCHAR(255) NULL,
  created_at BIGINT NOT NULL,
  correlation_id VARCHAR(255) NOT NULL,
  page_start BIGINT UNSIGNED NULL,
  page_end BIGINT UNSIGNED NULL,
  page_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  evidence_code VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
  PRIMARY KEY (id),
  FOREIGN KEY (export_id) REFERENCES consent_archive_exports (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  FOREIGN KEY (actor_id) REFERENCES admins (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  CHECK (kind IN ('queued','preparing','ready','failed','download_requested','page_generated','stream_interrupted')),
  CHECK (actor_type IN ('admin','worker','recovery_cli')),
  CHECK (created_at >= 0),
  CHECK ((page_start IS NULL AND page_end IS NULL) OR (page_start IS NOT NULL AND page_end IS NOT NULL AND page_start<=page_end)),
  CHECK ((kind='page_generated' AND page_sha256 IS NOT NULL AND page_start IS NOT NULL) OR (kind<>'page_generated' AND page_sha256 IS NULL)),
  KEY ix_care_export (export_id,created_at,id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TRIGGER d5_1_update BEFORE UPDATE ON event_info_plans FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='append only record';
CREATE TRIGGER d5_1_delete BEFORE DELETE ON event_info_plans FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='append only record';
CREATE TRIGGER d5_2_update BEFORE UPDATE ON event_info_plan_events FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='append only record';
CREATE TRIGGER d5_2_delete BEFORE DELETE ON event_info_plan_events FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='append only record';
CREATE TRIGGER d5_3_update BEFORE UPDATE ON event_info_apply_attempts FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='append only record';
CREATE TRIGGER d5_3_delete BEFORE DELETE ON event_info_apply_attempts FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='append only record';
CREATE TRIGGER d5_4_update BEFORE UPDATE ON event_info_apply_observations FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='append only record';
CREATE TRIGGER d5_4_delete BEFORE DELETE ON event_info_apply_observations FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='append only record';
CREATE TRIGGER d5_7_update BEFORE UPDATE ON consent_archive_items FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='append only record';
CREATE TRIGGER d5_7_delete BEFORE DELETE ON consent_archive_items FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='append only record';
CREATE TRIGGER d5_8_update BEFORE UPDATE ON consent_archive_events FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='append only record';
CREATE TRIGGER d5_8_delete BEFORE DELETE ON consent_archive_events FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='append only record';

CREATE INDEX ix_consents_event_time_seq ON consents(event_id,accepted_at_utc,seq);
-- REVIEW ONLY. No schema or index changes have been applied.
-- Additional index candidate for schema 5; column definitions remain those of docs4.
CREATE INDEX ix_eipe_import_source ON event_info_plan_events(reason_code,kind,note(96));
-- Prefix query under target lock + existing write lock:
-- SELECT plan_id FROM event_info_plan_events
-- WHERE reason_code=? AND kind=? AND note LIKE ? LIMIT 1;
-- Bind only ('legacy_import','created','legacy-import|<validated SHA256>|%').
-- This is an application-serialized uniqueness rule, not a UNIQUE constraint.
