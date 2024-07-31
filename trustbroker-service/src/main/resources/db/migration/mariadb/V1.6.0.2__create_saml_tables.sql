-- SAML Artifact Cache
CREATE TABLE TB_SAML_ARTIFACT_CACHE
(
	ARTIFACT_ID          VARCHAR(255) PRIMARY KEY NOT NULL,
	EXPIRATION_TIMESTAMP TIMESTAMP NOT NULL,
	DATA                 MEDIUMTEXT
) ENGINE = InnoDB;

-- 2nd key indexes
-- session termination by reaper only
CREATE INDEX IDX_EXPIRATION_TIMESTAMP ON TB_SAML_ARTIFACT_CACHE(EXPIRATION_TIMESTAMP);
