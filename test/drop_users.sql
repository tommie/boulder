-- Before setting up any privileges, we revoke existing ones to make sure we
-- start from a clean slate.
-- Note that dropping a non-existing user produces an error that aborts the
-- script, so we first grant a harmless privilege to each user to ensure it
-- exists.
SET SESSION sql_mode = 'NO_ENGINE_SUBSTITUTION';
GRANT USAGE ON *.* TO 'policy'@'%';
DROP USER 'policy'@'%';
GRANT USAGE ON *.* TO 'sa'@'%';
DROP USER 'sa'@'%';
GRANT USAGE ON *.* TO 'ocsp_resp'@'%';
DROP USER 'ocsp_resp'@'%';
GRANT USAGE ON *.* TO 'ocsp_update'@'%';
DROP USER 'ocsp_update'@'%';
GRANT USAGE ON *.* TO 'revoker'@'%';
DROP USER 'revoker'@'%';
GRANT USAGE ON *.* TO 'importer'@'%';
DROP USER 'importer'@'%';
GRANT USAGE ON *.* TO 'mailer'@'%';
DROP USER 'mailer'@'%';
GRANT USAGE ON *.* TO 'cert_checker'@'%';
DROP USER 'cert_checker'@'%';

