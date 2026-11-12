/**
 * Copyright (c) 2012 - 2026 Data In Motion and others.
 * All rights reserved.
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 *     Data In Motion - initial API and implementation
 */
package org.gecko.bnd.update;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import aQute.lib.io.IO;
import aQute.lib.json.JSONCodec;

/**
 * The vulnerabilities of a Trivy JSON report ({@code trivy sbom --format json}), grouped by the
 * library they were reported for. Only Maven libraries ({@code groupId:artifactId}) are kept.
 */
public final class TrivyReport {

	private final Map<Library, List<Vulnerability>> vulnerabilities;

	private TrivyReport(Map<Library, List<Vulnerability>> vulnerabilities) {
		this.vulnerabilities = vulnerabilities;
	}

	@SuppressWarnings("unchecked")
	public static TrivyReport read(InputStream in) throws Exception {
		Map<String, Object> report = new JSONCodec().dec()
			.from(IO.collect(in))
			.get(Map.class);
		Map<Library, List<Vulnerability>> result = new LinkedHashMap<>();
		if (report.get("Results") instanceof List<?> results) {
			for (Object r : results) {
				if (!(r instanceof Map<?, ?> res) || !(res.get("Vulnerabilities") instanceof List<?> vulns)) {
					continue;
				}
				for (Object v : vulns) {
					Map<String, Object> vuln = (Map<String, Object>) v;
					String name = string(vuln.get("PkgName"));
					String installed = string(vuln.get("InstalledVersion"));
					int colon = name != null ? name.indexOf(':') : -1;
					if (colon <= 0 || installed == null) {
						continue;
					}
					Library library = new Library(name.substring(0, colon), name.substring(colon + 1), installed);
					List<String> fixed = new ArrayList<>();
					String fixedVersion = string(vuln.get("FixedVersion"));
					if (fixedVersion != null) {
						for (String f : fixedVersion.split(",")) {
							if (!f.isBlank()) {
								fixed.add(f.trim());
							}
						}
					}
					result.computeIfAbsent(library, k -> new ArrayList<>())
						.add(new Vulnerability(string(vuln.get("VulnerabilityID")), string(vuln.get("Severity")), fixed,
							string(vuln.get("Title"))));
				}
			}
		}
		return new TrivyReport(result);
	}

	/** The vulnerable libraries with their vulnerabilities, in report order. */
	public Map<Library, List<Vulnerability>> vulnerabilities() {
		return vulnerabilities;
	}

	private static String string(Object value) {
		return value != null ? value.toString() : null;
	}
}
