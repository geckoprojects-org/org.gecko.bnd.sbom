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

import java.io.InputStream;
import java.util.List;
import java.util.Properties;

import org.gecko.bnd.sbom.model.MavenCoordinates;
import org.gecko.bnd.sbom.model.SbomTool;

import aQute.bnd.osgi.About;

/**
 * The tools that write the SBOM: this exporter and the bnd it runs in (#15).
 * <p>
 * The exporter's identity comes from {@code tool.properties}, which bnd writes into the jar at
 * build time ({@code -includeresource.tool} in bnd.bnd). It is read as a resource of this class:
 * bnd loads plugins through its {@code ActivelyClosingClassLoader}, which defines classes without
 * a code source and answers resources with {@code bndloader:} URLs, parent first — so no jar path
 * is available, but a resource that only this jar has is found. Running from a class directory
 * (tests, IDE) the file is missing; then only the name is known.
 */
public final class Tools {

	static final String						EXPORTER_NAME	= "org.gecko.bnd.sbom";

	private static volatile List<SbomTool>	tools;

	private Tools() {}

	public static List<SbomTool> current() {
		List<SbomTool> result = tools;
		if (result == null) {
			result = List.of(exporter(), bnd());
			tools = result;
		}
		return result;
	}

	static SbomTool bnd() {
		return new SbomTool("biz.aQute.bnd", "bnd", About.CURRENT.toString(), "bndtools", null);
	}

	static SbomTool exporter() {
		Properties properties = new Properties();
		try (InputStream in = Tools.class.getResourceAsStream("tool.properties")) {
			if (in == null) {
				return new SbomTool(null, EXPORTER_NAME, null, null, null);
			}
			properties.load(in);
		} catch (Exception e) {
			return new SbomTool(null, EXPORTER_NAME, null, null, null);
		}
		String vendor = blankToNull(properties.getProperty("vendor"));
		MavenCoordinates coordinates = MavenCoordinates.of(properties.getProperty("groupId"),
			properties.getProperty("artifactId"), properties.getProperty("version"), null, null);
		if (coordinates == null) {
			return new SbomTool(null, EXPORTER_NAME, blankToNull(properties.getProperty("bundleVersion")), vendor,
				null);
		}
		return new SbomTool(coordinates.groupId(), coordinates.artifactId(), coordinates.version(), vendor,
			Purl.maven(coordinates));
	}

	private static String blankToNull(String value) {
		return value == null || value.isBlank() ? null : value.trim();
	}
}
