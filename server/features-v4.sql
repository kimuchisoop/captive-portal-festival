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
