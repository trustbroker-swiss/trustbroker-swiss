/*
 * Copyright (C) 2024 trustbroker.swiss team BIT
 * 
 * This program is free software.
 * You can redistribute it and/or modify it under the terms of the GNU Affero General Public License
 * as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * 
 * See the GNU Affero General Public License for more details.
 * You should have received a copy of the GNU Affero General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>. 
 */

package swiss.trustbroker.script.service;


import java.io.File;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.script.Bindings;
import javax.script.Compilable;
import javax.script.CompiledScript;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.Response;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.setup.service.GitService;
import swiss.trustbroker.common.util.CollectionUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.IdmQuery;
import swiss.trustbroker.federation.xmlconfig.Script;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.oidc.session.HttpExchangeSupport;
import swiss.trustbroker.saml.dto.CpResponse;
import swiss.trustbroker.saml.dto.RpRequest;
import swiss.trustbroker.util.WebSupport;

/**
 * Service implements flexibility hooks for the XTB Processing Model.
 * Specifically the scripts hooks specified in XTB Configuration.
 */
@Service
@Slf4j
public class ScriptService {

	private static final String DIRECTORY_LATEST = GitService.CONFIGURATION_PATH_SUB_DIR_LATEST;

	// hooks we support
	private static final String SCRIPT_TYPE_BEFORE_IDM = "BeforeIdm";

	private static final String SCRIPT_TYPE_AFTER_IDM = "AfterIdm";

	private static final String SCRIPT_TYPE_BEFORE_HRD = "BeforeHrd";

	private static final String SCRIPT_TYPE_OIDC_ON_TOKEN = "OnToken"; // OIDC claims enrichment

	private static final String SCRIPT_TYPE_OIDC_ON_USERINFO = "OnUserInfo"; // OIDC claims reducer

	private static final String SCRIPT_TYPE_ON_SAML_REQUEST = "OnRequest"; // validation hook

	private static final String SCRIPT_TYPE_ON_CP_REQUEST = "OnCpRequest"; // outbound hook

	private static final String SCRIPT_TYPE_ON_SAML_RESPONSE= "OnResponse"; // validation hook

	// beans that groovy scripts can access directly by these names (Camel case with first character uppercase)
	private static final String BEAN_LOGGER = "LOG";

	private static final String BEAN_HTTP_REQUEST = "HTTPRequest"; // just the servlet spec interface

	private static final String BEAN_RP_REQUEST = "RPRequest"; // state we pass through processing i.e. RpRequest

	private static final String BEAN_CP_RESPONSE = "CPResponse"; // state we pass through processing i.e. CpResponse

	private static final String BEAN_SAML_RESPONSE = "SAMLResponse"; // CP Response

	private static final String BEAN_SAML_REQUEST = "SAMLRequest"; // RP AuthRequest in opensaml dom API

	private static final String BEAN_IDM_QUERIES = "IDMQueryList"; // map of queries we shall execute

	private static final String BEAN_RP_CONFIG = "RPConfig"; // RP config to allow config interaction

	private static final String CLAIM_VALUES = "ClaimValues"; // OIDC value converters

	// the only script language we currently support
	private static final String LANG_GROOVY = "groovy";

	private static final String VALUE_CONVERTER_POSTFIX = "-converter." + LANG_GROOVY;

	private final ScriptEngine scriptEngine;

	private final Compilable compilingEngine;

	// for re-config support always use via getScriptsMap
	private Map<String, CompiledScript> compiledScriptsMap;

	private final TrustBrokerProperties trustBrokerProperties;

	private final RelyingPartySetupService relyingPartySetupService;

	public ScriptService(TrustBrokerProperties trustBrokerProperties,
			RelyingPartySetupService relyingPartySetupService) {
		this.trustBrokerProperties = trustBrokerProperties;
		this.relyingPartySetupService = relyingPartySetupService;
		var factory = new ScriptEngineManager();
		compiledScriptsMap = new HashMap<>(); // not thread-safe
		try {
			scriptEngine = factory.getEngineByName(LANG_GROOVY);
			compilingEngine = (Compilable) scriptEngine;
		}
		catch (Exception e) {
			throw new TechnicalException("Could not load engine for script language '" + LANG_GROOVY + "': " + e, e);
		}
		if (compilingEngine == null) {
			throw new TechnicalException("Could not find script engine on classpath for language " + LANG_GROOVY);
		}

		log.info("Scripting support for language '{}' added", LANG_GROOVY);
	}

	// testing use only, for runtime re-config do not use it from outside
	protected void init(String scriptName) {
		Assert.notNull(scriptName, "Missing mandatory property 'scriptName'");
		var scriptSrc = new ScriptSource(scriptName);
		var compiledScript = scriptSrc.loadScript(compilingEngine);
		if (compiledScript != null) {
			getScriptsMap().put(scriptName, compiledScript);
		}
	}

	// RP side script hooks

	public void processHrdSelection(RpRequest rpRequest, HttpServletRequest request) {
		var scripts = getScriptsByType(rpRequest.getRpIssuer(), rpRequest.getReferer(),	SCRIPT_TYPE_BEFORE_HRD, true);
		for (Script script : scripts) {
			processOnRequest(SCRIPT_TYPE_BEFORE_HRD, script.getName(), request, rpRequest, null);
		}
	}

	public void processRequestValidation(RpRequest rpRequest, HttpServletRequest request, RequestAbstractType samlRequest) {
		var scripts = getScriptsByType(rpRequest.getRpIssuer(), rpRequest.getReferer(), SCRIPT_TYPE_ON_SAML_REQUEST, true);
		for (Script script : scripts) {
			processOnRequest(SCRIPT_TYPE_ON_SAML_REQUEST, script.getName(), request, rpRequest, samlRequest);
		}
	}

	public void processCpBeforeIdm(CpResponse cpResponse, Response response, String requestIssuer, String referrer) {
		var scripts = getScriptsByType(requestIssuer, referrer, SCRIPT_TYPE_BEFORE_IDM, false);
		processAllSamlScripts(SCRIPT_TYPE_BEFORE_IDM, scripts, cpResponse, response, null);
	}

	public void processRpAfterIdm(CpResponse cpResponse, Response response, String requestIssuer, String referrer) {
		var scripts = getScriptsByType(requestIssuer, referrer, SCRIPT_TYPE_AFTER_IDM, true);
		processAllSamlScripts(SCRIPT_TYPE_AFTER_IDM, scripts, cpResponse, response, null);
	}

	public void processOnResponse(CpResponse cpResponse, Response response, String requestIssuer, String referrer) {
		var scripts = getScriptsByType(requestIssuer, referrer, SCRIPT_TYPE_ON_SAML_RESPONSE, true);
		processAllSamlScripts(SCRIPT_TYPE_ON_SAML_RESPONSE, scripts, cpResponse, response, null);
	}

	// CP side script hooks

	public void processRequestToCp(String cpIssuer, RequestAbstractType samlRequest) {
		List<Script> scripts = getScriptsByType(cpIssuer, null, SCRIPT_TYPE_ON_CP_REQUEST, false);
		for (Script script : scripts) {
			processOnRequest(SCRIPT_TYPE_ON_CP_REQUEST, script.getName(), null, null, samlRequest);
		}
	}

	public void processRpBeforeIdm(CpResponse cpResponse, Response response, String requestIssuer, String referrer) {
		var scripts = getScriptsByType(requestIssuer, referrer, SCRIPT_TYPE_BEFORE_IDM, true);
		processAllSamlScripts(SCRIPT_TYPE_BEFORE_IDM, scripts, cpResponse, response, null);
	}

	// OIDC script hooks
	public void processRpOnToken(CpResponse cpResponse, String requestIssuer, String referrer) {
		var scripts = getScriptsByType(requestIssuer, referrer, SCRIPT_TYPE_OIDC_ON_TOKEN, true);
		processAllOidcScripts(SCRIPT_TYPE_OIDC_ON_TOKEN, scripts, cpResponse, null);
	}

	public void processRpOnUserInfo(CpResponse cpResponse, String requestIssuer, String referrer) {
		var scripts = getScriptsByType(requestIssuer, referrer, SCRIPT_TYPE_OIDC_ON_USERINFO, true);
		processAllOidcScripts(SCRIPT_TYPE_OIDC_ON_USERINFO, scripts, cpResponse, null);
	}

	public void processAllOidcScripts(String hookType, List<Script> scripts, CpResponse cpResponse,
									  Response response) {
		for (Script script : scripts) {
			processOnResponse(hookType, script.getName(), cpResponse, response, null);
		}
	}

	public void processAllSamlScripts(String hookType, List<Script> scripts,
									  CpResponse cpResponse, Response response, List<IdmQuery> idmQueries) {
		for (Script script : scripts) {
			processOnResponse(hookType, script.getName(), cpResponse, response, idmQueries);
		}
	}

	// On unit testing it's not very relevant which hook it is
	protected void processOnRequest(String scriptName, HttpServletRequest httpServletRequest, RpRequest rpRequest,
						  RequestAbstractType samlRequest)
			throws TechnicalException {
		processOnRequest("TestStep", scriptName, httpServletRequest, rpRequest, samlRequest);
	}

	// SAML request and a SPRquest object could be future use, for now we keep it small for SPS19 only
	void processOnRequest(String hookType, String scriptName,
			HttpServletRequest httpServletRequest, RpRequest rpRequest, RequestAbstractType samlRequest)
			throws TechnicalException {
		var compiledScript = getScriptsMap().get(scriptName);
		if (compiledScript == null) {
			throw new TechnicalException(String.format("Failed to load compiled script name '%s'", scriptName));
		}
		var bindings = bindRequestBeans(httpServletRequest, rpRequest, samlRequest);
		try {
			if (log.isTraceEnabled()) {
				log.trace("Executing step={} script={} using {}={} {}={} {}={}",
						hookType, scriptName,
						BEAN_HTTP_REQUEST, WebSupport.getTraceId(),
						BEAN_RP_REQUEST, rpRequest,
						BEAN_SAML_REQUEST, OpenSamlUtil.samlObjectToString(samlRequest));
			}
			compiledScript.eval(bindings);
		}
		catch (Exception e) {
			throw new TechnicalException(String.format("Failed to process script '%s'.  Details: %s", scriptName, e), e);
		}
	}

	// On unit testing it's not very relevant which hook it is
	protected void processOnResponse(String scriptName, CpResponse cpResponse, Response response, List<IdmQuery> idmQueries)
			throws TechnicalException {
		processOnResponse("TestStep", scriptName, cpResponse, response, idmQueries);
	}

	void processOnResponse(String hookType, String scriptName,
						   CpResponse cpResponse, Response response,
						   List<IdmQuery> idmQueries) throws TechnicalException {
		var compiledScript = getScriptsMap().get(scriptName);
		if (compiledScript == null) {
			throw new TechnicalException(String.format("Failed to load compiled script name '%s'", scriptName));
		}
		var bindings = bindResponseBeans(cpResponse, response, idmQueries);
		try {
			if (log.isTraceEnabled()) {
				log.trace("Executing step={} script={} using {}={} {}={} {}={}",
						hookType, scriptName,
						BEAN_CP_RESPONSE, cpResponse,
						BEAN_SAML_RESPONSE, OpenSamlUtil.samlObjectToString(response),
						BEAN_IDM_QUERIES, idmQueries == null ? idmQueries : Arrays.toString(idmQueries.toArray()));
			}
			compiledScript.eval(bindings);
		}
		catch (Exception e) {
			throw new TechnicalException(String.format("Failed to evaluate script '%s'.  Details: %s", scriptName, e), e);
		}
	}

	public List<Object> processValueConversion(String attributeName, List<Object> values) throws TechnicalException {
		var derivedScriptName = attributeName + VALUE_CONVERTER_POSTFIX;
		var compiledScript = getScriptsMap().get(derivedScriptName);
		if (compiledScript == null) {
			throw new TechnicalException(String.format("Failed to find converter script name '%s'", derivedScriptName));
		}
		var bindings = scriptEngine.createBindings();
		bindings.put(CLAIM_VALUES, values);
		try {
			if (log.isTraceEnabled()) {
				log.trace("Executing step=ConvertOdcValue script={}", derivedScriptName);
			}
			return CollectionUtil.asList(compiledScript.eval(bindings));
		}
		catch (Exception e) {
			throw new TechnicalException(String.format("Failed to evaluate script '%s'.  Details: %s",
					derivedScriptName, e), e);
		}
	}

	private Bindings bindRequestBeans(HttpServletRequest httpServletRequest, RpRequest rpRequest,
									  RequestAbstractType samlRequest) {
		var bindings = scriptEngine.createBindings();
		// input
		bindings.put(BEAN_RP_CONFIG, relyingPartySetupService);  // undocumented, unused (even dangerous when modified)
		if (httpServletRequest != null) {
			bindings.put(BEAN_HTTP_REQUEST, httpServletRequest);  // undocumented, unused (even dangerous when modified)
		}
		bindings.put(BEAN_SAML_REQUEST, samlRequest);  // SAML message validation
		// input/output
		if (rpRequest != null) {
			bindings.put(BEAN_RP_REQUEST, rpRequest); // undocumented, unused (even dangerous when modified)
		}
		// output
		bindings.put(BEAN_LOGGER, log); // documented
		return bindings;
	}

	private Bindings bindResponseBeans(CpResponse cpResponse, Response response, List<IdmQuery> idmQueries) {
		var bindings = scriptEngine.createBindings();
		// input (undocumented, unused, just in case)
		bindings.put(BEAN_RP_CONFIG, relyingPartySetupService);  // even dangerous when modified
		bindings.put(BEAN_SAML_RESPONSE, response); // null in OIDC hooks
		bindings.put(BEAN_IDM_QUERIES, idmQueries); // null in OIDC, even dangerous when modified
		bindings.put(BEAN_HTTP_REQUEST, HttpExchangeSupport.getRunningHttpRequest()); // allow some HTTP wire based decisions
		// input/output (documented)
		bindings.put(BEAN_CP_RESPONSE, cpResponse); // documented, used, our main vehicle for SAML  manipulations
		bindings.put(BEAN_LOGGER, log);
		return bindings;
	}

	public void refresh() {
		var tempCompiledScriptsMap = new HashMap<String, CompiledScript>();
		var configurationPath = trustBrokerProperties.getConfigurationPath();
		var scriptPath = trustBrokerProperties.getScriptPath();
		var scriptFullPath =	configurationPath + DIRECTORY_LATEST + scriptPath;
		var scriptsDir = new File(scriptFullPath);
		var fileNames = scriptsDir.listFiles();
		if (fileNames != null) {
			Arrays.stream(fileNames).forEach(file -> {
				log.debug("Loading script {} from {}", file.getName(), file.getAbsolutePath());
				var scriptSource = new ScriptSource(file.getAbsolutePath());
				var compiledScript = scriptSource.loadScript(compilingEngine);
				if (compiledScript != null) {
					tempCompiledScriptsMap.put(file.getName(), compiledScript);
				}
			});
		}
		switchScriptsMap(tempCompiledScriptsMap);
	}

	private List<Script> getScriptsByType(String issuerId, String refererUrl, String type, boolean rpSide) {
		var scripts = rpSide ?
				relyingPartySetupService.getRpScripts(issuerId, refererUrl) :
				relyingPartySetupService.getCpScripts(issuerId, refererUrl);
		var ret = scripts.stream()
				.filter(script -> script != null && script.getType().equalsIgnoreCase(type))
				.toList();
		log.debug("Found allScriptsCount={} for issuer={} stepType={} on {} side usingScriptsCount={}",
				scripts.size(), issuerId, type, rpSide ? "RP" : "CP", ret.size());
		return ret;
	}

	// for refreshs we need to make sure switch over does not lead to concurrent modification exceptions
	synchronized Map<String, CompiledScript> getScriptsMap() {
		return compiledScriptsMap;
	}

	// for refreshs we need to make sure switch over does not lead to concurrent modification exceptions
	private synchronized void switchScriptsMap(Map<String, CompiledScript> newScriptsMap) {
		log.debug("Activate scripts oldMap={} newMap={}", compiledScriptsMap.size(), newScriptsMap.size());
		compiledScriptsMap = newScriptsMap;
	}

}
