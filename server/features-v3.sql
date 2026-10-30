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
