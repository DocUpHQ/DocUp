-- SPDX-FileCopyrightText: 2026 The DocUp contributors
-- SPDX-License-Identifier: Apache-2.0
--
-- Make the audit log append-only to the application, and create the separate
-- maintenance principal (SPEC 8.22.1).
--
-- 🛑 Run this as a database ADMINISTRATOR, not as the application user. The
-- application cannot apply it, and that is not an oversight in the setup — it
-- is inherent. Both available mechanisms need privileges the application must
-- never hold:
--
--   * a table-level REVOKE needs a table-level GRANT to subtract from, and
--     MySQL 8's partial_revokes works at SCHEMA level, so "ALL on docup.* except
--     UPDATE on audit_events" cannot be expressed:
--         ERROR 1147: There is no such grant defined for user 'docup'
--                     on host '%' on table 'audit_events'
--
--   * CREATE TRIGGER requires SUPER while binary logging is enabled:
--         ERROR 1419: You do not have the SUPER privilege and binary logging
--                     is enabled
--
-- So an audit log that the application genuinely cannot rewrite requires a
-- privileged bootstrap. `docup:doctor` verifies the result and FAILS when it is
-- absent, so an installation that skipped this step is told so rather than
-- quietly keeping a forgeable log.
--
-- On the development stack this runs automatically: it is mounted into
-- /docker-entrypoint-initdb.d, which the MySQL image executes as root on first
-- initialisation. On an existing installation, run it by hand:
--
--     mysql -u root -p < deploy/mysql/init/10-audit-append-only.sql
--
-- Idempotent: safe to run again.
--
-- Covers the `docup` schema only. The development stack's `docup_test` schema
-- gets 20-audit-append-only-test.sql, mounted by compose.dev.yaml, for the same
-- reason MailPit lives there: a production installation must not carry it.

-- ---------------------------------------------------------------------------
-- The maintenance principal (SPEC 8.22.1)
-- ---------------------------------------------------------------------------
-- Partition management and retention purging only. Its credentials belong in
-- the scheduled maintenance job, NOT in the application container.
--
-- 🛑 Change this password. It is here so a fresh development stack works, and
-- it is the only credential in this file for that reason.
CREATE USER IF NOT EXISTS 'docup_maintenance'@'%' IDENTIFIED BY 'docup-maintenance';

-- ALTER, CREATE and INSERT are what MySQL requires for ALTER TABLE … ADD
-- PARTITION; DROP is for retention by DROP PARTITION.
GRANT SELECT, INSERT, CREATE, ALTER, DROP ON `docup`.`audit_events` TO 'docup_maintenance'@'%';
GRANT SELECT, DELETE ON `docup`.`audit_anchors` TO 'docup_maintenance'@'%';

-- ---------------------------------------------------------------------------
-- Append-only enforcement
-- ---------------------------------------------------------------------------
-- Honest about what this does and does not cover: it stops UPDATE and DELETE,
-- which is how a log gets quietly rewritten. It does NOT stop DROP TABLE or
-- TRUNCATE, and whoever can drop the trigger can remove the protection. It is
-- strictly stronger than the application holding ALL PRIVILEGES, and weaker
-- than a grant that cannot be expressed.
--
-- Retention is unaffected: SPEC 20.3 purges events by DROP PARTITION, which is
-- not a DELETE and never reaches a row trigger.

DELIMITER $$

DROP TRIGGER IF EXISTS `docup`.`audit_events_no_update`$$
CREATE TRIGGER `docup`.`audit_events_no_update` BEFORE UPDATE ON `docup`.`audit_events`
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_events is append-only (SPEC 8.22.1)';
END$$

DROP TRIGGER IF EXISTS `docup`.`audit_events_no_delete`$$
CREATE TRIGGER `docup`.`audit_events_no_delete` BEFORE DELETE ON `docup`.`audit_events`
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_events is append-only; purge by DROP PARTITION (SPEC 20.3)';
END$$

DROP TRIGGER IF EXISTS `docup`.`audit_anchors_no_update`$$
CREATE TRIGGER `docup`.`audit_anchors_no_update` BEFORE UPDATE ON `docup`.`audit_anchors`
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'an anchor may never be re-signed (SPEC 8.22.1)';
END$$

-- Anchors ARE purged by row under SPEC 20.3, so the maintenance principal is
-- allowed through. SESSION_USER() is the account that connected, unlike
-- CURRENT_USER() which would be the trigger's definer and make this vacuous.
DROP TRIGGER IF EXISTS `docup`.`audit_anchors_no_delete`$$
CREATE TRIGGER `docup`.`audit_anchors_no_delete` BEFORE DELETE ON `docup`.`audit_anchors`
FOR EACH ROW
BEGIN
    IF SUBSTRING_INDEX(SESSION_USER(), '@', 1) <> 'docup_maintenance' THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'only the maintenance principal may purge anchors (SPEC 8.22.1)';
    END IF;
END$$

DELIMITER ;

FLUSH PRIVILEGES;
