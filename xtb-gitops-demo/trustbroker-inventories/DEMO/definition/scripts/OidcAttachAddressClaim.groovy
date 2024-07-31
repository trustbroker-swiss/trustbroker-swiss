// Purpose: Show how OIDC claim enrichment and structured claim assembly works.
// Note: Implements https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim

// some IDP provided attributes
givenName = "" + CPResponse.getAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname")
familiyName = "" + CPResponse.getAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname")
// derive OIDC displayName from SAML incoming attributes as OIDC claim only
CPResponse.addClaim("name", givenName + " " + familiyName + " (source:3)")

// derive address from SAML attributes and construct new claim without honoring incoming request scopes
if (CPResponse.oidcScopes && CPResponse.oidcScopes.contains("openid")) {
	CPResponse.addJsonClaim("address", "street_address", "123 " + familiyName + " Street")
	CPResponse.addJsonClaim("address", "locality", "St. " + familiyName)
	CPResponse.addJsonClaim("address", "postal_code", "9999")
	CPResponse.addJsonClaim("address", "country", "Switzerland")
	LOG.info("OnToken hook attached a fake address for clientId={} scopes='{}'", CPResponse.oidcClientId, CPResponse.oidcScopes)
}