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
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.SerializationUtils;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderDefinitions;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderRelyingParty;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderSetup;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.RelyingPartySetup;
import swiss.trustbroker.federation.xmlconfig.SsoGroupSetup;

@SuppressWarnings("unchecked")
@Slf4j
public class ClaimsProviderUtil {

	static class LoadResult <T> {

		List<T> result = new ArrayList<>();

		int skipped = 0;
	}

	private ClaimsProviderUtil() {
	}

	// handle all SetupCP*.xml files
	// handle all SetupCP*.xml files
	public static ClaimsProviderSetup loadClaimsProviderSetup(String mappingFile) {
		var start = System.currentTimeMillis(); // we read from PVC residing on a network appliance
		var mapping = new File(mappingFile);
		var allCps = loadConfigFromDirectory(mapping, ClaimsProviderSetup.class);
		var ret = new ClaimsProviderSetup();
		allCps.result.forEach(cps -> ret.getClaimsParties().addAll(cps.getClaimsParties()));
		ret.getClaimsParties().forEach(ClaimsProviderUtil::postInit);
		reportDuplicateClaimsParties(ret.getClaimsParties());
		log.info("Loaded {}Count={} definitions from setupCpFileCount={} {} files (skipping invalidCount={}) in dtMs={}",
				ClaimsParty.class.getSimpleName(), ret.getClaimsParties().size(), allCps.result.size(),
				mapping.getName(), allCps.skipped, System.currentTimeMillis() - start);
		return ret;
	}

	private static void postInit(ClaimsParty claimsParty) {
		// transition of configs
	}

	// handle all SetupRP*.xml files
	public static RelyingPartySetup loadRelyingPartySetup(String mappingFile) {
		return loadRelyingPartySetup(new File(mappingFile));
	}

	public static RelyingPartySetup loadRelyingPartySetup(File mappingFile) {
		var start = System.currentTimeMillis(); // we read from PVC residing on a network appliance
		var allRps = loadConfigFromDirectory(mappingFile, RelyingPartySetup.class);
		var ret = new RelyingPartySetup();
		allRps.result.forEach(rps -> ret.getRelyingParties().addAll(rps.getRelyingParties()));
		var countWithoutAliases = ret.getRelyingParties().size();
		var rpIds = reportDuplicatRelyingParties(ret.getRelyingParties());
		replicateRelyingPartiesByHrdAlias(ret.getRelyingParties(), rpIds); // register aliases
		var countWithAliases = ret.getRelyingParties().size();
		var oidcClientCount = new AtomicLong();
		ret.getRelyingParties().forEach(rp -> oidcClientCount.addAndGet(rp.getOidcClients().size()));
		log.info("Loaded {}Count={} definitions from setupRpFileCount={} {} files "
						+"(adding relyingPartyAliasCount={} oidcClientCount={}  skipping invalidCount={}) in dtMs={}",
				RelyingParty.class.getSimpleName(), countWithoutAliases, allRps.result.size(),
				mappingFile.getName(), (countWithAliases - countWithoutAliases), oidcClientCount, allRps.skipped,
				System.currentTimeMillis() - start);
		return ret;
	}

	private static Set<String> reportDuplicatRelyingParties(List<RelyingParty> relyingParties) {
		var idSet = new HashSet<String>();
		for (var relyingParty : relyingParties) {
			if (idSet.contains(relyingParty.getId())) {
				log.error("Duplicate relyingPartyId={}", relyingParty.getId());
			}
			idSet.add(relyingParty.getId());
		}
		return idSet;
	}


	private static Set<String> reportDuplicateClaimsParties(List<ClaimsParty> claimsParties) {
		var idSet = new HashSet<String>();
		for (var claimsParty : claimsParties) {
			if (idSet.contains(claimsParty.getId())) {
				log.error("Duplicate claimsPartyId={}", claimsParty.getId());
			}
			idSet.add(claimsParty.getId());
		}
		return idSet;
	}

	public static RelyingParty loadRelyingParty(String mappingFile) {
		var mapping = new File(mappingFile);
		return XmlConfigUtil.loadConfigFromFile(mapping, RelyingParty.class);
	}

	public static ClaimsProviderDefinitions loadClaimsProviderDefinitions(String mappingFile) {
		var start = System.currentTimeMillis(); // we read from PVC residing on a network appliance
		var mapping = new File(mappingFile);
		var ret = XmlConfigUtil.loadConfigFromFile(mapping, ClaimsProviderDefinitions.class);
		log.info("Loaded {}Count={} definitions from one {} file in dtMs={}",
				ClaimsProviderDefinitions.class.getSimpleName(), ret.getClaimsProviders().size(),
				mapping.getName(), System.currentTimeMillis() - start);
		return ret;
	}

	public static SsoGroupSetup loadSsoGroups(String ssoGroupsSetupFileName) {
		var ssoGroupsSetupFile = new File(ssoGroupsSetupFileName);
		if (!ssoGroupsSetupFile.exists()) {
			// we have too many setup files and SSOGroups are special, so get rid of the Setup prefix in a backward compat way
			ssoGroupsSetupFile = new File(ssoGroupsSetupFileName.replace("SetupSSOGroups", "SSOGroups"));
		}
		return XmlConfigUtil.loadConfigFromFile(ssoGroupsSetupFile, SsoGroupSetup.class);
	}

	public static boolean mustUpdate(String newFile, String oldFile) {
		var file1 = new File(newFile);
		var file2 = new File(oldFile);
		try {
			boolean equals = FileUtils.contentEquals(file1, file2);
			return !equals;
		}
		catch (IOException e) {
			log.error("Reading files for update error", e);
		}
		return false;
	}

	// load multiple files
	static <T> LoadResult<T> loadConfigFromDirectory(File mappingFile, Class<T> entryType) {
		var ret = new LoadResult<T>();
		var definitionDirectory = mappingFile.getParentFile();
		if (definitionDirectory == null || !definitionDirectory.isDirectory()) {
			log.error("Cannot iterate over directory {}", definitionDirectory);
			return ret;
		}
		File[] allFiles = definitionDirectory.listFiles();
		if (allFiles == null) {
			log.error("Encountered empty directory {}", definitionDirectory.getParentFile());
			return ret;
		}
		// SetupXY.xml => SetupXY
		var fileExtension = ".xml";
		String setupXy = mappingFile.getName().replace(fileExtension, "");
		for (File file : allFiles) {
			if (file.getName().startsWith(setupXy) && file.getName().endsWith(fileExtension)) {
				try {
					ret.result.add(XmlConfigUtil.loadConfigFromFile(file, entryType));
				}
				catch (TechnicalException ex) {
					if (log.isDebugEnabled()) {
						log.error("Could not load config: {}", ex.getInternalMessage(), ex);
					}
					else {
						log.error("Could not load config: {}", ex.getInternalMessage()); // exception stack too verbose
					}
					++ret.skipped;
				}
			}
		}
		return ret;
	}

	// handle derived IDs, so we can merge RelyingParty X with X-...
	public static void replicateRelyingPartiesByHrdAlias(List<RelyingParty> relyingParties, Set<String> rpIds) {
		var aliasList = new ArrayList<RelyingParty>();
		relyingParties.forEach(relyingParty -> {
			log.debug("Adding primary rpIssuer={}", relyingParty.getId());
			var mappings = relyingParty.getClaimsProviderMappings();
			if (mappings != null) {
				var claimProviders = mappings.getClaimsProviderList();
				if (claimProviders != null) {
					claimProviders.forEach(claimProvider ->
						addAliasesForClaimsProvider(rpIds, aliasList, relyingParty, claimProvider)
					);
				}
			}
		});
		relyingParties.addAll(aliasList);
	}

	private static void addAliasesForClaimsProvider(Set<String> rpIds,
			ArrayList<RelyingParty> aliasList, RelyingParty relyingParty, ClaimsProviderRelyingParty claimProvider) {
		var alias = claimProvider.getRelyingPartyAlias();
		if (alias != null) {
			var rpAliasCopy = SerializationUtils.clone(relyingParty);
			rpAliasCopy.setUnaliasedId(rpAliasCopy.getId());
			rpAliasCopy.setId(alias);
			if (rpIds.contains(rpAliasCopy.getId())) {
				log.error("Adding duplicate alias={} for rpIssuer={} skipped."
								+ " HINT: Check SetupRP files for ambiguous 'id' and 'relyingPartyAlias' attributes.",
						alias, relyingParty.getId());
			}
			else {
				aliasList.add(rpAliasCopy);
				rpIds.add(alias);
				log.debug("Adding alias={} for rpIssuer={}", alias, relyingParty.getId());
			}
		}
	}

}
