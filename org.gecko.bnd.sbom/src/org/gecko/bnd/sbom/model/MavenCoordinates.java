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
package org.gecko.bnd.sbom.model;

/**
 * Verified Maven identity of a component: group, artifact and Maven version (not the OSGi
 * Bundle-Version), plus classifier and extension where the repository knows them. Only built
 * when group, artifact and version are all present.
 *
 * @param classifier may be {@code null}
 * @param extension may be {@code null} (then {@code jar})
 */
public record MavenCoordinates(String groupId, String artifactId, String version, String classifier,
	String extension) {

	/**
	 * @return the coordinates, or {@code null} if group, artifact or version is missing (an
	 *         incomplete coordinate must not become a component identity — Q3)
	 */
	public static MavenCoordinates of(String groupId, String artifactId, String version, String classifier,
		String extension) {
		if (isBlank(groupId) || isBlank(artifactId) || isBlank(version)) {
			return null;
		}
		return new MavenCoordinates(groupId.trim(), artifactId.trim(), version.trim(), blankToNull(classifier),
			blankToNull(extension));
	}

	private static boolean isBlank(String value) {
		return value == null || value.isBlank();
	}

	private static String blankToNull(String value) {
		return isBlank(value) ? null : value.trim();
	}
}
