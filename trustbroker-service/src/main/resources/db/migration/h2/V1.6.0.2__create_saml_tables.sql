DROP TABLE IF EXISTS TB_SAML_ARTIFACT_CACHE;
CREATE TABLE IF NOT EXISTS TB_SAML_ARTIFACT_CACHE
(
	ARTIFACT_ID          VARCHAR(255) PRIMARY KEY NOT NULL ,
	EXPIRATION_TIMESTAMP TIMESTAMP NOT NULL,
	DATA                 MEDIUMTEXT
);