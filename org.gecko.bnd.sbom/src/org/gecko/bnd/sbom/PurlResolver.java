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

import java.io.File;
import java.io.InputStream;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;

import org.gecko.bnd.sbom.model.MavenCoordinates;

import aQute.bnd.build.Container;
import aQute.bnd.build.Project;
import aQute.bnd.maven.MavenCapability;
import aQute.bnd.osgi.Jar;
import aQute.bnd.osgi.Resource;
import aQute.libg.glob.PathSet;

/**
 * Resolves a bundle's identity into a Package URL (PURL) in stages — see
 * requirements/anforderungen-sbom-schichten.md Q3:
 * <ol>
 * <li>repository provenance: the Maven GAV that {@code MavenBndRepository} attaches to the
 * {@code Container} as {@code maven-*} attributes (authoritative)</li>
 * <li>{@code META-INF/maven/**}{@code /pom.properties} inside the JAR</li>
 * </ol>
 * If both fail: return {@code null} → the caller marks the component as unverified
 * (Q3.b/Q4) <b>without</b> inventing a PURL — a wrong PURL silently breaks the CVE link.
 * <p>
 * Mirrors the two-tier algorithm bnd itself uses in
 * {@code ProjectBuilder.fillDependencies}.
 */
public final class PurlResolver {

	private static final PathSet POM_PROPERTIES = new PathSet("META-INF/maven/*/*/pom.properties");

	@SuppressWarnings("unused")
	private final Project project;

	public PurlResolver(Project project) {
		this.project = project;
	}

	/**
	 * @return the verified Maven coordinates, or {@code null} if the identity cannot be
	 *         determined reliably.
	 */
	public MavenCoordinates resolve(Container container) throws Exception {
		// getFile() forces the download blocker's maven-* attributes to be merged in.
		File file = container.getFile();

		MavenCoordinates fromAttributes = fromContainerAttributes(container.getAttributes());
		if (fromAttributes != null) {
			return fromAttributes;
		}

		if (file != null && file.isFile()) {
			return fromPomProperties(file);
		}
		return null;
	}

	/** Step 1 (authoritative): the GAV the Maven repository attached to the container. */
	private static MavenCoordinates fromContainerAttributes(Map<String, String> attributes) {
		return MavenCoordinates.of(attributes.get(MavenCapability.CAPABILITY_GROUPID_ATTRIBUTE),
			attributes.get(MavenCapability.CAPABILITY_ARTIFACTID_ATTRIBUTE),
			attributes.get(MavenCapability.CAPABILITY_VERSION_ATTRIBUTE),
			attributes.get(MavenCapability.CAPABILITY_CLASSIFIER_ATTRIBUTE),
			attributes.get(MavenCapability.CAPABILITY_EXTENSION_ATTRIBUTE));
	}

	/** Step 2 (fallback): the first {@code pom.properties} embedded in the JAR. */
	private static MavenCoordinates fromPomProperties(File file) throws Exception {
		try (Jar jar = new Jar(file)) {
			Optional<Resource> pom = jar.getResources(POM_PROPERTIES.matches())
				.findFirst();
			if (!pom.isPresent()) {
				return null;
			}
			Properties props = new Properties();
			try (InputStream in = pom.get()
				.openInputStream()) {
				props.load(in);
			}
			// pom.properties has no classifier/extension; a plain jar coordinate is fine.
			return MavenCoordinates.of(props.getProperty("groupId"), props.getProperty("artifactId"),
				props.getProperty("version"), null, null);
		}
	}
}
