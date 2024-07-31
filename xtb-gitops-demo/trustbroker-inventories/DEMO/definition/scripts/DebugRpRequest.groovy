// Purpose: Dump bound SP request date to console (bindings, see ScriptService.java)
// Note: Consider documentation and RPRequest.java members that should be used in scripts.
LOG.debug("DEMO: Process federation request from referer {}", HTTPRequest.getHeader("Referer"))
LOG.trace("DEMO RPRequest: {}", RPRequest)
