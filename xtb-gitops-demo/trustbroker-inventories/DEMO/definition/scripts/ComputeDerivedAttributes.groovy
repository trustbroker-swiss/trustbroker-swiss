// Purpose: Show how derived properties work..
import java.text.SimpleDateFormat

// some IDP provided attributes
givenName = "" + CPResponse.getAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname")
familiyName = "" + CPResponse.getAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname")
dateofbirth = "" + CPResponse.getAttribute("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/dateofbirth")

// derive displayName as OIDC claim
CPResponse.addProperty("displayName", "2.16.840.1.113730.3.1.241", givenName + " " + familiyName + " (source:2)")

// transcode birthdate claim from SAML to OIDC
if (dateofbirth && dateofbirth.length() == 15) {
	inFormat = new SimpleDateFormat("yyyyMMddHHmmSSX")
	outFormat = new SimpleDateFormat("yyy-MM-dd")
	dateInternal = inFormat.parse(dateofbirth)
	birthdate = outFormat.format(dateInternal)
	LOG.info("Transforming incoming dateofbirth={} to OIDC birthdate={}", dateofbirth, birthdate)

	// override incoming (not recommended, as it's marked with OriginalIssuer not from XTB)
	//CPResponse.setAttribute("dateOfBirth", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/dateofbirth", birthdate)

	// add as derived attribute (correctly declares it as a claim XTB computed)
	CPResponse.setProperty("dateOfBirth", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/dateofbirth", birthdate)

	// using an IDM service it's also possible set it as part of the user details selection (not part of DEMO setup though)
	CPResponse.addUserDetail("dateOfBirth", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/dateofbirth", birthdate)

	// add as OIDC claim only (only relevant when script runs OnToken) -->
	CPResponse.setClaim("birthdate", birthdate)
}
