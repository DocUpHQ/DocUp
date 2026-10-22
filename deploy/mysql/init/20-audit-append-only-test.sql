-- SPDX-FileCopyrightText: 2026 The DocUp contributors
-- SPDX-License-Identifier: Apache-2.0
--
-- The same append-only guards for the `docup_test` schema (SPEC 8.22.1).
--
-- 🛑 Development only. Mounted by compose.dev.yaml, never by compose.yaml, for
-- the same reason MailPit and phpMyAdmin are absent from production (§8.1.3):
-- a production installation has no test schema and must not carry setup that
-- assumes one.
--
-- It exists so that tests/Feature/AuditAppendOnlyTest.php can prove the
-- application connection is actually refused, rather than asserting that a
-- SQL file says it would be. A test that runs against an unhardened schema
-- would pass while proving nothing.

GRANT SELECT, INSERT, CREATE, ALTER, DROP ON `docup_test`.`audit_events` TO 'docup_maintenance'@'%';
GRANT SELECT, DELETE ON `docup_test`.`audit_anchors` TO 'docup_maintenance'@'%';

DELIMITER $$

DROP TRIGGER IF EXISTS `docup_test`.`audit_events_no_update`$$
CREATE TRIGGER `docup_test`.`audit_events_no_update` BEFORE UPDATE ON `docup_test`.`audit_events`
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_events is append-only (SPEC 8.22.1)';
END$$

DROP TRIGGER IF EXISTS `docup_test`.`audit_events_no_delete`$$
CREATE TRIGGER `docup_test`.`audit_events_no_delete` BEFORE DELETE ON `docup_test`.`audit_events`
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_events is append-only; purge by DROP PARTITION (SPEC 20.3)';
END$$

DROP TRIGGER IF EXISTS `docup_test`.`audit_anchors_no_update`$$
CREATE TRIGGER `docup_test`.`audit_anchors_no_update` BEFORE UPDATE ON `docup_test`.`audit_anchors`
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'an anchor may never be re-signed (SPEC 8.22.1)';
END$$

DROP TRIGGER IF EXISTS `docup_test`.`audit_anchors_no_delete`$$
CREATE TRIGGER `docup_test`.`audit_anchors_no_delete` BEFORE DELETE ON `docup_test`.`audit_anchors`
FOR EACH ROW
BEGIN
    IF SUBSTRING_INDEX(SESSION_USER(), '@', 1) <> 'docup_maintenance' THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'only the maintenance principal may purge anchors (SPEC 8.22.1)';
    END IF;
END$$

DELIMITER ;

FLUSH PRIVILEGES;
