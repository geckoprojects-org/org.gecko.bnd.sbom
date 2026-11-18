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
package org.gecko.bnd.sbom;

import java.util.ArrayList;
import java.util.List;

import org.gecko.bnd.sbom.model.SbomComponent;
import org.gecko.bnd.sbom.model.SbomLevel;
import org.gecko.bnd.sbom.model.SbomModel;
import org.gecko.bnd.sbom.serializer.SbomFormat;

/**
 * Checks a model against the required data fields of BSI TR-03183-2 v2.1.0 ({@code validate=
 * bsi-tr-03183-2}). It only reports; the SBOM is written as it is.
 * <p>
 * Which fields a component needs depends on its kind (TR §5.1):
 * <ul>
 * <li><b>identified</b> (§3.2.4) — a component outside the scope of delivery (the Java runtime,
 * with its minimum version) or a library shaded into a bundle, which is no file of its own:
 * creator, name, version</li>
 * <li><b>fully described</b> (§5.2.2) — every delivered file: in addition filename, distribution
 * licence, SHA-512 hash and the executable, archive and structured properties</li>
 * </ul>
 * The completeness of the dependencies (§5.2.2) is always declared by the exporter.
 */
public final class BsiTr03183Validator {

	private BsiTr03183Validator() {}

	/** The findings, one per SBOM-level gap and one per component with gaps; empty when conformant. */
	public static List<String> validate(SbomModel model, SbomConfig config) {
		List<String> findings = new ArrayList<>();
		if (!config.level()
			.includes(SbomLevel.MEDIUM)) {
			findings.add("BSI TR-03183-2 needs level=medium or higher; level=" + config.level()
				.id() + " leaves out hash, filename, licence and file properties");
			return findings;
		}
		// TR §4: SPDX ≥ 3.0.1 or CycloneDX ≥ 1.6 (the CycloneDX versions offered are all ≥ 1.6)
		if (config.format() == SbomFormat.SPDX) {
			findings.add("BSI TR-03183-2 requires SPDX 3.0.1 or later; this exporter writes SPDX 2.3 — use "
				+ "format=cyclonedx for a conformant SBOM");
		}
		// TR §5.2.1
		if (model.getCreator() == null || !model.getCreator()
			.isIdentified()) {
			findings.add("SBOM and application: no creator (email address or URL); set Bundle-ContactAddress or "
				+ "Bundle-DocURL in the project of the .bndrun, or 'creator' in -sbom");
		}
		for (SbomComponent component : model.getAllComponents()) {
			List<String> missing = missing(component);
			if (!missing.isEmpty()) {
				findings.add(describe(component) + ": missing " + String.join(", ", missing));
			}
		}
		return findings;
	}

	private static List<String> missing(SbomComponent component) {
		List<String> missing = new ArrayList<>();
		if (!component.hasCreator()) {
			missing.add("creator (email address or URL)");
		}
		if (name(component) == null) {
			missing.add("name");
		}
		if (version(component) == null) {
			missing.add("version");
		}
		if (isIdentifiedOnly(component)) {
			return missing;
		}
		if (component.getFilename() == null) {
			missing.add("filename");
		}
		if (component.getLicenses()
			.isEmpty()) {
			missing.add("distribution licence");
		}
		if (component.getSha512() == null) {
			missing.add("SHA-512 hash");
		}
		if (!component.hasFileProperties()) {
			missing.add("executable/archive/structured properties");
		}
		return missing;
	}

	/**
	 * Outside the scope of delivery (minimum version) or no file of its own (a library shaded into
	 * a bundle): identified, not fully described.
	 */
	static boolean isIdentifiedOnly(SbomComponent component) {
		return component.isMinimumVersion() || component.isLogical()
			|| component.getEmbeddedPath() != null && component.getFilename() == null;
	}

	private static String name(SbomComponent component) {
		return component.getMaven() != null ? component.getMaven()
			.artifactId() : component.getBsn();
	}

	private static String version(SbomComponent component) {
		return component.getMaven() != null ? component.getMaven()
			.version() : component.getVersion();
	}

	private static String describe(SbomComponent component) {
		if (component.getPurl() != null) {
			return component.getPurl();
		}
		String name = name(component) != null ? name(component) : "component";
		String version = version(component);
		return version != null ? name + "@" + version : name;
	}
}
