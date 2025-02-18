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

package swiss.trustbroker.homerealmdiscovery.util;

import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.util.CollectionUtils;
import swiss.trustbroker.api.idm.dto.IdmRequest;
import swiss.trustbroker.api.idm.service.IdmService;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.util.DirectoryUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.AcWhitelist;
import swiss.trustbroker.federation.xmlconfig.ArtifactBinding;
import swiss.trustbroker.federation.xmlconfig.AttributesSelection;
import swiss.trustbroker.federation.xmlconfig.AuthorizedApplication;
import swiss.trustbroker.federation.xmlconfig.Certificates;
import swiss.trustbroker.federation.xmlconfig.ConstAttributes;
import swiss.trustbroker.federation.xmlconfig.CounterParty;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.Encryption;
import swiss.trustbroker.federation.xmlconfig.Flow;
import swiss.trustbroker.federation.xmlconfig.FlowPolicies;
import swiss.trustbroker.federation.xmlconfig.IdmLookup;
import swiss.trustbroker.federation.xmlconfig.IdmQuery;
import swiss.trustbroker.federation.xmlconfig.Oidc;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.federation.xmlconfig.ProfileSelection;
import swiss.trustbroker.federation.xmlconfig.ProtocolEndpoints;
import swiss.trustbroker.federation.xmlconfig.Qoa;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.Saml;
import swiss.trustbroker.federation.xmlconfig.Script;
import swiss.trustbroker.federation.xmlconfig.Scripts;
import swiss.trustbroker.federation.xmlconfig.SecurityPolicies;
import swiss.trustbroker.federation.xmlconfig.Signature;
import swiss.trustbroker.federation.xmlconfig.SignerKeystore;
import swiss.trustbroker.federation.xmlconfig.SignerTruststore;
import swiss.trustbroker.federation.xmlconfig.Sso;
import swiss.trustbroker.federation.xmlconfig.SubjectNameMappings;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.saml.dto.CpResponse;
import swiss.trustbroker.saml.dto.ResponseParameters;
import swiss.trustbroker.script.service.ScriptService;
import swiss.trustbroker.util.PropertyUtil;

@Slf4j
public class RelyingPartySetupUtil {

	public static final String DEFINITION_PATH = "definition/";

	private RelyingPartySetupUtil() {
	}

	public static void loadRelyingParty(Collection<RelyingParty> relyingParties, String definitionPath, String pullConfigPath,
			TrustBrokerProperties trustBrokerProperties, List<IdmService> idmServices, ScriptService scriptService) {
		if (relyingParties == null) {
			throw new TechnicalException("RelyingParties are missing or could not be loaded");
		}
		for (RelyingParty relyingParty : relyingParties) {
			try {
				loadRelyingParty(definitionPath, pullConfigPath, relyingParty, trustBrokerProperties, idmServices, scriptService);
			}
			catch (TechnicalException ex) {
				log.error("Could not load base claim: {}", ex.getInternalMessage());
				relyingParty.invalidate(ex);
			}
		}
	}

	private static void loadRelyingParty(String definitionPath, String pullConfigPath, RelyingParty relyingParty,
			TrustBrokerProperties trustBrokerProperties, List<IdmService> idmServices, ScriptService scriptService) {
		var baseRule = relyingParty.getBase();

		if (!StringUtils.isBlank(baseRule)) {
			var rulePath = resolvePath(definitionPath, pullConfigPath, baseRule, relyingParty.getSubPath(), trustBrokerProperties);
			var basePath = Path.of(rulePath, baseRule).toString();
			var baseClaim = ClaimsProviderUtil.loadRelyingParty(basePath);
			mergeRelyingParty(relyingParty, baseClaim, idmServices);
			applyGlobalCertificates(relyingParty, trustBrokerProperties);
			validateScripts(relyingParty, scriptService);
		}

		postInit(relyingParty);
	}

	public static void validateScripts(CounterParty counterParty, ScriptService scriptService) {
		if (scriptService == null || counterParty.getScripts() == null) {
			return;
		}
		for (var script : counterParty.getScripts().getScripts()) {
			// validate against the scripts prepared for rollover:
			if (!scriptService.isScriptValid(script.getName(), counterParty.getSubPath(), false)) {
				log.error("Script={} is not valid for {} id={}",
						script.getName(), counterParty.getShortType(), counterParty.getId());
				counterParty.invalidate(String.format("Script type=%s name=%s is not valid", script.getType(), script.getName()));
			}
		}
	}

	private static String resolvePath(String definitionPath, String pullConfigPath, String baseRule, String subPath,
			TrustBrokerProperties trustBrokerProperties) {
		// see ReferenceHolder for the order
		var pullConfigDefinition = pullConfigPath + DEFINITION_PATH;
		if (StringUtils.isNotEmpty(subPath)) {
			// 1. relative path in definition
			var path = findInConfigOrCache(definitionPath + subPath, pullConfigDefinition + subPath, baseRule);
			if (path != null) {
				log.trace("Found baseRule={} in subPath={} : path={}", baseRule, subPath, path);
				return path;
			}
		}
		var globalProfilesPath = trustBrokerProperties != null ? trustBrokerProperties.getGlobalProfilesPath() : null;
		if (StringUtils.isNotEmpty(globalProfilesPath)) {
			// 2. global profile directory
			var path = findInConfigOrCache(definitionPath + globalProfilesPath, pullConfigDefinition + globalProfilesPath, baseRule);
			if (path != null) {
				log.trace("Found baseRule={} in globalProfilesPath={} : path={}", baseRule, globalProfilesPath, path);
				return path;
			}
		}
		var path = findInConfigOrCache(definitionPath, pullConfigDefinition, baseRule);
		if (path != null) {
			log.trace("Found baseRule={} in definition path : path={}", baseRule, path);
			return path;
		}
		throw new TechnicalException(String.format("Provided base=%s does not exist in definitions=%s or cache=%s directly, "
								+ "or within globalProfilesPath=%s or subPath=%s",
					baseRule, definitionPath, pullConfigPath, globalProfilesPath, subPath));
	}

	private static String findInConfigOrCache(String definitionPath, String pullConfigDefinition, String baseRule) {
		var baseInConfig = Path.of(definitionPath, baseRule).toFile();
		var baseInCache = Path.of(pullConfigDefinition, baseRule).toFile();
		var baseInConfigExists = baseInConfig.exists();
		var baseInCacheExists = baseInCache.exists();
		var differentBase = baseInConfigExists && baseInCacheExists &&
				DirectoryUtil.contentDiffers(baseInConfig, baseInCache);
		if ((!baseInConfigExists && baseInCacheExists) || differentBase) {
			return pullConfigDefinition;
		}
		if (baseInConfigExists) {
			return definitionPath;
		}
		return null;
	}

	private static void postInit(RelyingParty relyingParty) {
		if (relyingParty.getAcWhitelist() != null) {
			relyingParty.getAcWhitelist().calculateDerivedUrls(); // as we read from XML, constructors and setters were ignore
		}
		// same for OIDC AC lists
		if (relyingParty.getOidc() != null && relyingParty.getOidc().getClients() != null) {
			relyingParty.getOidc().getClients().forEach(c -> {
				if (c.getRedirectUris() != null) {
					c.getRedirectUris().calculateDerivedUrls();
					if (CollectionUtils.isEmpty(c.getRedirectUris().getRedirectUrls())) {
						log.error("Invalid rpIssuerId={} oidcClient={} - empty redirect URL list derived from "
								+ "ACUrls={}", relyingParty.getId(), c.getId(), c.getRedirectUris().getAcUrls());
							// such a client would fail when building the OIDC registry
						relyingParty.invalidate("Empty redirect URL list derived from ACUrls");
					}
				}
			});
		}
	}

	private static void mergeCpAttributes(RelyingParty relyingParty, AttributesSelection baseAttributes) {
		var attributesSelection = relyingParty.getAttributesSelection();
		if (attributesSelection == null || attributesSelection.getDefinitions() == null) {
			relyingParty.setAttributesSelection(baseAttributes);
		}
		else if (baseAttributes != null && baseAttributes.getDefinitions() != null) {
			List<Definition> collect = joinAndDistinctDefinitions(attributesSelection.getDefinitions(),
					baseAttributes.getDefinitions());
			attributesSelection.setDefinitions(collect);
		}
	}

	static void mergeRelyingParty(RelyingParty relyingParty, RelyingParty baseRelyingParty, List<IdmService> idmServices) {
		if (relyingParty == null) {
			throw new TechnicalException("RelyingParty is missing");
		}
		if (baseRelyingParty == null) {
			return;
		}

		//SSO
		var baseRelyingPartySso = baseRelyingParty.getSso();
		mergeSsoConfig(relyingParty, baseRelyingPartySso);

		// Qoa
		mergeQoaLevels(relyingParty, baseRelyingParty);

		// AccessRequest
		mergeAccessRequest(relyingParty, baseRelyingParty);

		//SecurityPolicies
		var baseRelyingPartySecurityPolicies = baseRelyingParty.getSecurityPolicies();
		mergeSecurityPoliciesConfig(relyingParty, baseRelyingPartySecurityPolicies);

		//AssertionConsumer whitelist
		var baseAcWhitelist = baseRelyingParty.getAcWhitelist();
		mergeAcWhiteList(relyingParty, baseAcWhitelist);

		//SubjectNameMappings
		var baseSubjectNameMappings = baseRelyingParty.getSubjectNameMappings();
		mergeSubjectNameMappings(relyingParty, baseSubjectNameMappings);

		//Profile selection
		var baseProfileSelection = baseRelyingParty.getProfileSelection();
		mergeProfileSelection(relyingParty, baseProfileSelection);

		//CP Response Attributes
		var baseCpAttributeSelection = baseRelyingParty.getAttributesSelection();
		mergeCpAttributes(relyingParty, baseCpAttributeSelection);

		// Properties
		var basePropertiesSelection = baseRelyingParty.getPropertiesSelection();
		mergePropertiesSelection(relyingParty, basePropertiesSelection);

		// Oidc
		mergeOidc(relyingParty, baseRelyingParty.getOidc());

		// Saml
		mergeSaml(relyingParty, baseRelyingParty.getSaml());

		// FlowPolicies
		mergeFlowPolicies(relyingParty, baseRelyingParty.getFlowPolicies());

		//Groovy
		var baseGroovy = baseRelyingParty.getScripts();
		mergeScripts(relyingParty, baseGroovy);

		//Constant attributes
		var baseClaimConstAttributes = baseRelyingParty.getConstAttributes();
		mergeConstantAttributes(relyingParty, baseClaimConstAttributes);

		//IDMQueries
		if (baseRelyingParty.getIdmLookup() != null) {
			if (relyingParty.getIdmLookup() == null) {
				relyingParty.setIdmLookup(baseRelyingParty.getIdmLookup());
			}
			else {
				mergeMultiQueryPolicy(relyingParty, baseRelyingParty);
				mergeIdmQueries(relyingParty, baseRelyingParty.getIdmLookup(), idmServices);
			}
		}

		// Certificates
		mergeCertificates(relyingParty, baseRelyingParty);
	}

	private static void mergeMultiQueryPolicy(RelyingParty relyingParty, RelyingParty baseRelyingParty) {
		var rpMultiQueryPolicy = relyingParty.getIdmLookup().getMultiQueryPolicy();
		var baseMultiQueryPolicy = baseRelyingParty.getIdmLookup().getMultiQueryPolicy();
		if (rpMultiQueryPolicy == null && baseMultiQueryPolicy != null) {
			relyingParty.getIdmLookup().setMultiQueryPolicy(baseMultiQueryPolicy);
		}
	}

	// Make <Certificates/> optional using global settings as last resort for all SetupRP/ProfileRP files
	private static void applyGlobalCertificates(RelyingParty relyingParty, TrustBrokerProperties trustBrokerProperties) {
		if (trustBrokerProperties == null || trustBrokerProperties.getSigner() == null) {
			// unit tests only
			return;
		}
		if (relyingParty.getCertificates() == null) {
			relyingParty.setCertificates(Certificates.builder().build());
		}
		var certSetup = relyingParty.getCertificates();
		String signerCertPath = extractCertName(trustBrokerProperties.getSigner().getSignerCert());
		String signerKeyPath = extractCertName(trustBrokerProperties.getSigner().getSignerKey());
		if (certSetup.getSignerKeystore() == null && trustBrokerProperties.getSigner() != null) {
			var globalSigner = SignerKeystore.builder()
											 .certPath(signerCertPath)
											 .password(trustBrokerProperties.getSigner().getPassword())
											 .certType(trustBrokerProperties.getSigner().getType())
											 .alias(trustBrokerProperties.getSigner().getKeyEntryId())
											 .keyPath(signerKeyPath)
											 .build();
			certSetup.setSignerKeystore(globalSigner);
		}
		// trust ourselves as a last resort to not have a 'null' truststore
		if (certSetup.getSignerTruststore() == null && trustBrokerProperties.getSigner() != null) {

			var globalTrust = SignerTruststore.builder()
											  .certPath(signerCertPath)
											  .password(trustBrokerProperties.getSigner().getPassword())
											  .certType(trustBrokerProperties.getSigner().getType())
											  .alias(trustBrokerProperties.getSigner().getKeyEntryId())
											  .keyPath(signerKeyPath)
											  .build();
			certSetup.setSignerTruststore(globalTrust);
		}
	}

	// In global config certPath contains the whole path, but on load the path is completed
	private static String extractCertName(String certPath) {
		if (certPath == null) {
			return null;
		}
		return new File(certPath).getName();
	}

	private static void mergeOidc(RelyingParty relyingParty, Oidc baseOidc) {
		if (baseOidc == null || baseOidc.getClients() == null || baseOidc.getClients().isEmpty()
				|| relyingParty.getOidc() == null || relyingParty.getOidc().getClients() == null) {
			return;
		}

		relyingParty.getOidc().getClients().forEach(client -> mergeOidcClient(client, baseOidc.getClients().get(0)));
	}

	protected static void mergeOidcClient(OidcClient client, OidcClient baseClient) {
		PropertyUtil.copyMissingAttributes(client, baseClient);
	}

	private static void mergeSaml(RelyingParty relyingParty, Saml baseSaml) {
		if (baseSaml == null) {
			return;
		}
		mergeEncryption(relyingParty, baseSaml.getEncryption());
		mergeSignature(relyingParty, baseSaml.getSignature());
		mergeProtocolEndpoints(relyingParty, baseSaml.getProtocolEndpoints());
		mergeArtifactBinding(relyingParty, baseSaml.getArtifactBinding());
	}

	private static void mergeFlowPolicies(RelyingParty relyingParty, FlowPolicies baseFlowPolicies) {
		if (baseFlowPolicies == null) {
			return;
		}
		if (relyingParty.getFlowPolicies() == null) {
			relyingParty.setFlowPolicies(baseFlowPolicies);
			return;
		}
		// RP Flow with same ID wins
		Map<String, Flow> flowMap = new HashMap<>();
		baseFlowPolicies.getFlows().stream().forEachOrdered(flow -> flowMap.put(flow.getId(), flow));
		relyingParty.getFlowPolicies().getFlows().stream().forEachOrdered(flow -> flowMap.put(flow.getId(), flow));
		var flowList = new ArrayList<>(flowMap.values());
		relyingParty.getFlowPolicies()
					.setFlows(flowList);
	}

	private static void mergeEncryption(RelyingParty relyingParty, Encryption baseEncryption) {
		if (baseEncryption == null) {
			return;
		}
		PropertyUtil.copyMissingAttributes(relyingParty.initializedSaml().initializedEncryption(), baseEncryption);
	}

	private static void mergeSignature(RelyingParty relyingParty, Signature baseSignature) {
		if (baseSignature == null) {
			return;
		}
		PropertyUtil.copyMissingAttributes(relyingParty.initializedSaml().initializedSignature(), baseSignature);
	}

	private static void mergeProtocolEndpoints(RelyingParty relyingParty, ProtocolEndpoints baseProtocolEndpoints) {
		if (baseProtocolEndpoints == null) {
			return;
		}
		PropertyUtil.copyMissingAttributes(relyingParty.initializedSaml().initializedProtocolEndpoints(), baseProtocolEndpoints);
	}

	private static void mergeArtifactBinding(RelyingParty relyingParty, ArtifactBinding baseArtifactBinding) {
		if (baseArtifactBinding == null) {
			return;
		}
		PropertyUtil.copyMissingAttributes(relyingParty.initializedSaml().initializedArtifactBinding(), baseArtifactBinding);
	}


	static void mergeQoaLevels(RelyingParty relyingParty, RelyingParty baseRelyingParty) {
		Qoa rpQoa = relyingParty.getQoa();
		Qoa baseQoa = baseRelyingParty.getQoa();

		if (rpQoa == null) {
			relyingParty.setQoa(baseRelyingParty.getQoa());
		}
		else if (baseQoa != null && !baseQoa.getClasses().isEmpty()) {
			List<String> rpQoaClasses = rpQoa.getClasses();
			for (String qoa : baseQoa.getClasses()) {
				if (!rpQoaClasses.contains(qoa)) {
					rpQoaClasses.add(qoa);
				}
			}
		}
	}

	private static void mergeProfileSelection(RelyingParty relyingParty, ProfileSelection baseProfileSelection) {
		var profileSelection = relyingParty.getProfileSelection();
		if (profileSelection == null) {
			relyingParty.setProfileSelection(baseProfileSelection);
		}
	}

	private static void mergePropertiesSelection(RelyingParty relyingParty, AttributesSelection basePropertiesSelection) {
		var propertiesSelection = relyingParty.getPropertiesSelection();
		if (propertiesSelection == null || propertiesSelection.getDefinitions() == null) {
			relyingParty.setPropertiesSelection(basePropertiesSelection);
		}
		else if (basePropertiesSelection != null && basePropertiesSelection.getDefinitions() != null) {
			List<Definition> collect = joinAndDistinctDefinitions(propertiesSelection.getDefinitions(),
					basePropertiesSelection.getDefinitions());
			propertiesSelection.setDefinitions(collect);
		}
	}

	private static void mergeSsoConfig(RelyingParty relyingParty, Sso baseRelyingPartySso) {
		if (relyingParty.getSso() == null && baseRelyingPartySso != null) {
			relyingParty.setSso(baseRelyingPartySso); // enable/disable defined by profile so most likely always false
		}
	}

	static void mergeAccessRequest(RelyingParty relyingParty, RelyingParty baseRelyingParty) {
		try {
			if (!PropertyUtil.copyAttributeIfMissing(RelyingParty::setAccessRequest, RelyingParty::getAccessRequest,
					relyingParty, baseRelyingParty)) {
				var authorizedApplications = relyingParty.getAccessRequest().getAuthorizedApplications();
				var baseAuthorizedApplications = baseRelyingParty.getAccessRequest().getAuthorizedApplications();
				mergeAuthorizedApplications(authorizedApplications.getAuthorizedApplicationLists(),
						baseAuthorizedApplications.getAuthorizedApplicationLists());
			}
			// check for all cases, after merge
			if (relyingParty.getOidcClients().isEmpty()) {
				enforceSingleDefaultAccessRequestApplication(relyingParty);
			}
			// for OIDC multiple applications with no parameters are valid, the name is matched against the OIDC Client ID
		}
		catch (TechnicalException ex) {
			var accessRequest = relyingParty.getAccessRequest();
			if (accessRequest == null || !Boolean.TRUE.equals(accessRequest.getEnabled())) {
				log.error("AccessRequest not enabled for rpIssuerId={} - ignoring error: {}", relyingParty.getId(), ex.getInternalMessage());
			}
			else {
				throw ex;
			}
		}
	}

	private static void enforceSingleDefaultAccessRequestApplication(RelyingParty relyingParty) {
		if (relyingParty.getAccessRequest() == null) {
			return;
		}
		var authorizedApplications = relyingParty.getAccessRequest()
												 .getAuthorizedApplications()
												 .getAuthorizedApplicationLists();
		var defaultApplications = authorizedApplications.stream()
				.filter(AuthorizedApplication::isDefaultApplication)
				.toList();
		if (defaultApplications.size() > 1) {
			// provide the full list in the exception as we don't have the Profile ID here
			throw new TechnicalException(String.format("Configure exactly one AccessRequest default Authorized Application "
					+ "(without url/minQoa/oidcClientId) instead of %d: %s", defaultApplications.size(), defaultApplications));
		}
	}

	// 0 to 1 application defined for profile into 0 to n applications defined for RP
	private static void mergeAuthorizedApplications(List<AuthorizedApplication> targetApplications,
			List<AuthorizedApplication> baseApplications) {
		if (baseApplications.isEmpty()) {
			return;
		}
		if (baseApplications.size() != 1) {
			// provide the full list in the exception as we don't have the Profile ID here
			throw new TechnicalException(String.format("Configure exactly one AccessRequest Authorized Application for "
					+ "Profile instead of %d: %s", baseApplications.size(), baseApplications));
		}
		var baseApplication = baseApplications.get(0);
		if (targetApplications.isEmpty()) {
			targetApplications.add(baseApplication);
			return;
		}
		// no distinction between attributes that are specific to the RP and those that are usually defined per profile
		for (var targetApplication : targetApplications) {
			PropertyUtil.copyMissingAttributes(targetApplication, baseApplication);
		}
	}

	private static void mergeSecurityPoliciesConfig(RelyingParty relyingParty,
			SecurityPolicies baseRelyingPartySecurityPolicies) {
		PropertyUtil.copyMissingAttributes(relyingParty.getSecurityPolicies(), baseRelyingPartySecurityPolicies);
	}

	static void mergeAcWhiteList(RelyingParty relyingParty, AcWhitelist baseAcWhitelist) {
		var acWhitelist = relyingParty.getAcWhitelist();
		if (acWhitelist == null || CollectionUtils.isEmpty(acWhitelist.getAcUrls())) {
			// inherit from base
			relyingParty.setAcWhitelist(baseAcWhitelist);
		}
		else if (baseAcWhitelist != null) {
			// merge with base
			var collect = joinAndDistinctLists(acWhitelist.getAcUrls(), baseAcWhitelist.getAcUrls());
			acWhitelist.setAcUrls(collect);
		}
		// else: use what has been configured as is but make sure we internalized network URLs
		log.debug("RP rpId={} has merged acWhitelistUrls={} ", relyingParty.getId(),
				relyingParty.getAcWhitelist() != null ? relyingParty.getAcWhitelist().getAcUrls() : null);
	}

	static void mergeSubjectNameMappings(RelyingParty relyingParty, SubjectNameMappings baseSubjectNameMappings) {
		var subjectNameMappings = relyingParty.getSubjectNameMappings();
		if (subjectNameMappings == null || CollectionUtils.isEmpty(subjectNameMappings.getSubjects())) {
			relyingParty.setSubjectNameMappings(baseSubjectNameMappings);
		}
		else if (baseSubjectNameMappings != null) {
			subjectNameMappings.getSubjects().addAll(baseSubjectNameMappings.getSubjects());
		}
		// else: use what has been configured as is but make sure we internalized network URLs
		log.debug("RP rpId={} has merged subjectNameMappings={} ", relyingParty.getId(),
				relyingParty.getSubjectNameMappings() != null ? relyingParty.getSubjectNameMappings().getSubjects() : null);

	}

	static void mergeScripts(RelyingParty relyingParty, Scripts baseScripts) {
		var scripts = relyingParty.getScripts();
		if (scripts == null || scripts.getScripts() == null) {
			relyingParty.setScripts(baseScripts);
		}
		else if (baseScripts != null) {
			joinAndDistinctScripts(scripts, baseScripts);
			relyingParty.getScripts().setScripts(baseScripts.getScripts());
		}
	}

	static void joinAndDistinctScripts(Scripts scripts, Scripts baseScripts) {
		for (Script script : scripts.getScripts()) {
			if (script.getName() == null || script.getType() == null) {
				throw new TechnicalException(String.format("Script in RP with name=%s and type=%s has a null attribute",
						script.getName(), script.getType()));
			}
			if (scriptNotInBase(script, baseScripts)) {
				baseScripts.getScripts().add(script);
			}
		}
	}

	private static boolean scriptNotInBase(Script script, Scripts baseScripts) {
		for (Script baseScript : baseScripts.getScripts()) {
			if (baseScript.getName() == null || baseScript.getType() == null) {
				throw new TechnicalException(String.format("Script in Base profile with name=%s and type=%s has a null "
						+ "attribute", baseScript.getName(), baseScript.getType()));
			}
			if (baseScript.equals(script)) {
				return false;
			}
		}
		return true;
	}

	static void mergeConstantAttributes(RelyingParty relyingParty, ConstAttributes baseClaimConstAttributes) {
		var claimRuleConstAttributes = relyingParty.getConstAttributes();
		if (claimRuleConstAttributes == null || claimRuleConstAttributes.getAttributeDefinitions() == null ||
				claimRuleConstAttributes.getAttributeDefinitions().isEmpty()) {

			relyingParty.setConstAttributes(baseClaimConstAttributes);
		}
		else if (baseClaimConstAttributes != null) {
			List<Definition> collect = joinAndDistinctDefinitions(claimRuleConstAttributes.getAttributeDefinitions(),
					baseClaimConstAttributes.getAttributeDefinitions());

			claimRuleConstAttributes.setAttributeDefinitions(collect);
		}
	}

	static void mergeCertificates(RelyingParty relyingParty, RelyingParty baseClaim) {
		if (relyingParty.getCertificates() == null) {
			relyingParty.setCertificates(baseClaim.getCertificates());
		}
		else if (baseClaim.getCertificates() != null) {
			if (relyingParty.getCertificates().getSignerKeystore() == null) {
				relyingParty.getCertificates().setSignerKeystore(baseClaim.getCertificates().getSignerKeystore());
			}
			if (relyingParty.getCertificates().getSignerTruststore() == null) {
				relyingParty.getCertificates().setSignerTruststore(baseClaim.getCertificates().getSignerTruststore());
			}
			if (relyingParty.getCertificates().getEncryptionKeystore() == null) {
				relyingParty.getCertificates().setEncryptionKeystore(baseClaim.getCertificates().getEncryptionKeystore());
			}
		}
	}

	static void mergeIdmQueries(RelyingParty relyingParty, IdmLookup baseLookup, List<IdmService> idmServices) {
		if (baseLookup.getQueries() == null) {
			return;
		}

		for (IdmQuery baseIdmQuery : baseLookup.getQueries()) {
			mergeIdmQuery(relyingParty, baseIdmQuery);
		}
		sortIdmQueries(relyingParty, idmServices);
	}

	private static void mergeIdmQuery(RelyingParty relyingParty, IdmQuery baseIdmQuery) {
		var idmQuery = getExistingIdmQuery(relyingParty.getIdmLookup(), baseIdmQuery.getName(), baseIdmQuery.getId());
		if (idmQuery != null) {

			PropertyUtil.copyAttributeIfBlank(IdmQuery::setIssuerNameId, IdmQuery::getIssuerNameId, idmQuery, baseIdmQuery);

			PropertyUtil.copyAttributeIfBlank(IdmQuery::setIssuerNameIdNS, IdmQuery::getIssuerNameIdNS, idmQuery, baseIdmQuery);

			PropertyUtil.copyAttributeIfBlank(IdmQuery::setSubjectNameId, IdmQuery::getSubjectNameId, idmQuery, baseIdmQuery);

			PropertyUtil.copyAttributeIfMissing(IdmQuery::setStatusPolicy, IdmQuery::getStatusPolicy, idmQuery, baseIdmQuery);

			PropertyUtil.copyAttributeIfBlank(IdmQuery::setClientExtId, IdmQuery::getClientExtId, idmQuery, baseIdmQuery);

			if (StringUtils.isBlank(idmQuery.getClientExtId())) {
				log.error("Rp={} has no ClientExtId configured. IDMLookup will not work! "
						+ "Check the SetupRP and the corresponding RpProfile", relyingParty.getId());
			}

			PropertyUtil.copyAttributeIfBlank(IdmQuery::setAppFilter, IdmQuery::getAppFilter, idmQuery, baseIdmQuery);

			var baseIdmQueryResponseAttributes = baseIdmQuery.getUserDetailsSelection();
			mergeIdmRespAttributes(idmQuery, baseIdmQueryResponseAttributes);

			if (idmQuery.getUserDetailsSelection() == null || idmQuery.getUserDetailsSelection()
																	  .getDefinitions()
																	  .isEmpty()) {
				log.warn("Rp={} IDMQuery.name={} has no UserDetailsSelection list. No attribute will be picked "
								+ "from the IDM response. Check the SetupRP and the corresponding RpProfile",
						relyingParty.getId(), baseIdmQuery.getName());
			}

		}
		else {
			if (baseIdmQuery.getClientExtId() == null || baseIdmQuery.getUserDetailsSelection() == null) {
				// If everything id defined in the profile the query will work but most probably it will never be the case
				log.warn("Rp={} has no complete IDMQuery with expected IDMQuery.name={} in SetupRp.xml."
						+ "Check the SetupRP and the corresponding RpProfile", relyingParty.getId(), baseIdmQuery.getName());
			}
			relyingParty.getIdmLookup()
						.getQueries()
						.add(baseIdmQuery);
		}
	}


	private static void sortIdmQueries(RelyingParty relyingParty, List<IdmService> idmServices) {
		if (relyingParty.getIdmLookup() == null) {
			return;
		}
		for (IdmService idmService : idmServices) {
			List<IdmRequest> idmRequests = idmService.sortIdmRequests(relyingParty.getIdmLookup());
			relyingParty.getIdmLookup().updateIdmQueries(idmRequests);
		}
	}

	static void mergeIdmRespAttributes(IdmQuery idmQuery, AttributesSelection baseIdmQueryUserDetailsSelection) {
		var rpIDMUserDetailsSelection = idmQuery.getUserDetailsSelection();
		if (rpIDMUserDetailsSelection == null || rpIDMUserDetailsSelection.getDefinitions() == null
				|| rpIDMUserDetailsSelection.getDefinitions().isEmpty()) {
			idmQuery.setUserDetailsSelection(baseIdmQueryUserDetailsSelection);
		}
		else if (baseIdmQueryUserDetailsSelection != null) {
			List<Definition> collect = joinAndDistinctDefinitions(rpIDMUserDetailsSelection.getDefinitions(),
					baseIdmQueryUserDetailsSelection.getDefinitions());
			rpIDMUserDetailsSelection.setDefinitions(collect);
		}
	}

	// note: attributes is modified!
	static <T> List<T> joinAndDistinctLists(List<T> attributes, List<T> baseAttributes) {
		if (!CollectionUtils.isEmpty(baseAttributes)) {
			attributes.addAll(baseAttributes);
			return attributes.stream()
					.distinct()
					.toList();
		}
		return attributes;
	}

	static List<Definition> joinAndDistinctDefinitions(List<Definition> attributes, List<Definition> baseAttributes) {
		if (baseAttributes == null && attributes == null) {
			return Collections.emptyList();
		}
		else if (attributes == null) {
			return baseAttributes;
		}
		List<Definition> toRemoveFromBase = new ArrayList<>();
		if (baseAttributes != null && !baseAttributes.isEmpty()) {
			attributes = attributes.stream()
					.filter(attribute -> notInBaseOrHasOidcConf(baseAttributes, attribute, toRemoveFromBase))
					.collect(Collectors.toList());
			attributes.addAll(filterBaseAttributes(baseAttributes, toRemoveFromBase));
			return attributes;
		}
		return attributes;
	}

	private static List<Definition> filterBaseAttributes(List<Definition> baseAttributes, List<Definition> toRemoveFromBase) {
		if (!toRemoveFromBase.isEmpty()) {
			baseAttributes = baseAttributes.stream()
					.filter(attribute -> definitionInList(attribute, toRemoveFromBase).isEmpty())
					.toList();
		}
		return baseAttributes;
	}

	static boolean notInBaseOrHasOidcConf(List<Definition> baseAttributes, Definition attribute,
			List<Definition> toRemoveFromBase) {
		Optional<Definition> baseAttr = definitionInList(attribute, baseAttributes);
		if (baseAttr.isPresent()) {
			if (attribute.getOidcNames() != null && (attribute.getScope() != null || baseAttr.get().getOidcNames() == null)) {
				toRemoveFromBase.add(attribute);
				return true;
			}
			if (baseAttr.get().getOidcNames() != null) {
				return false;
			}
		}
		return baseAttr.isEmpty();
	}

	static Optional<Definition> definitionInList(Definition attributeDefinition, List<Definition> definitionList) {
		return definitionList.stream()
				.filter(attr -> attr.equalsByNameAndNamespace(attributeDefinition))
				.findFirst();
	}

	static IdmQuery getExistingIdmQuery(IdmLookup idmLookup, String idmQueryName, String baseQueryId) {
		if (idmLookup == null || idmLookup.getQueries() == null) {
			return null;
		}

		for (IdmQuery idmQuery : idmLookup.getQueries()) {
			if (idmQuery != null && baseQueryId != null && baseQueryId.equals(idmQuery.getId())) {
				return idmQuery;
			}
			if (idmQuery != null && baseQueryId == null && idmQuery.getName().equals(idmQueryName)) {
				return idmQuery;
			}
		}
		return null;
	}

	public static List<Definition> getIdpAttrDefinitions(CpResponse cpResponse, RelyingPartySetupService relyingPartySetupService,
			ResponseParameters params) {
		var idpAttributesDefinition = relyingPartySetupService.getRpAttributesDefinitions(
				params.getRpIssuerId(), params.getRpReferer());
		if (idpAttributesDefinition.isEmpty()) {
			idpAttributesDefinition = relyingPartySetupService.getCpAttributeDefinitions(
					cpResponse.getIssuer(), params.getRpIssuerId());
		}
		return idpAttributesDefinition;
	}

}
