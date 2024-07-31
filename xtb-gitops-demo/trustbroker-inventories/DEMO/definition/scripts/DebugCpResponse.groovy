// Purpose: Dump bound IDP response date to console (bindings, see ScriptService.java)
// Note: Consider documentation and CPResponse.java members that should be used in scripts.
LOG.debug("DEMO: Process federation response from referer {}", HTTPRequest.getHeader("Referer"))
LOG.trace("DEMO CPResponse: {}", CPResponse)
