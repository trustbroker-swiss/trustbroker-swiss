// Purpose: Show how user-agent context can be used to do IDP dispatching automatically.
// Example: Loadbalancer injecting a network identifier on the network perimeter.
// Security: Either loadbalancer shields the header or IDPs we forward to are save themselves.

strongIdp = "urn:trustbroker.swiss:idp:SAML-MOCK-2"
strongQoa = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract"

def isMobileStrongAuthOnly(rpRequest) {
	return rpRequest.contextClasses && rpRequest.contextClasses.size() == 1 && rpRequest.contextClasses.contains(strongQoa)
}

if (RPRequest.getClaimsProviders().size() > 1) {
	def networkDetected = HTTPRequest.getHeader("X-ClientNetwork")
	LOG.debug("Checking automatic HRD for rpIssuer={} with qoa={} from network={} towards cpMappings='{}'",
			RPRequest.rpIssuer, RPRequest.contextClasses, networkDetected, RPRequest.claimsProviders)
	if (isMobileStrongAuthOnly(RPRequest) || "INTRANET".equals(networkDetected)) {
		RPRequest.retainClaimsProvider(strongIdp)
		LOG.info("Automatic HRD for rpIssuer={} with qoa={} from network={} towards cpMappings='{}'",
				RPRequest.rpIssuer, RPRequest.contextClasses, networkDetected, RPRequest.claimsProviders)
	}
}
