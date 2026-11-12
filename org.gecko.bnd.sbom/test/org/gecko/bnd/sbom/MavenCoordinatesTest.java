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

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayOutputStream;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.gecko.bnd.sbom.model.MavenCoordinates;
import org.gecko.bnd.sbom.model.SbomComponent;
import org.gecko.bnd.sbom.model.SbomLevel;
import org.gecko.bnd.sbom.model.SbomModel;
import org.gecko.bnd.sbom.serializer.CycloneDxSerializer;
import org.gecko.bnd.sbom.serializer.SbomFormat;
import org.gecko.bnd.sbom.serializer.SpdxSerializer;
import org.junit.jupiter.api.Test;

import aQute.bnd.osgi.Resource;
import aQute.lib.json.JSONCodec;

/**
 * Maven coordinates as group/name/version, OSGi identity kept as properties (#14).
 */
public class MavenCoordinatesTest {

	private static final JSONCodec CODEC = new JSONCodec();

	private static final MavenCoordinates	SLF4J	= MavenCoordinates.of("org.slf4j", "slf4j-api", "2.0.17", null,
		null);

	private static SbomModel model() {
		return new SbomModel().setApplicationName("app")
			.addComponent(new SbomComponent().setBsn("slf4j.api")
				.setVersion("2.0.17.v2026")
				.setMaven(SLF4J)
				.setPurl(Purl.maven(SLF4J)))
			.addComponent(new SbomComponent().setBsn("legacy.bundle")
				.setVersion("0.9.0")
				.setUnverifiedIdentity(true));
	}

	@Test
	public void incompleteCoordinatesAreNoIdentity() {
		assertThat(MavenCoordinates.of(null, "a", "1", null, null)).isNull();
		assertThat(MavenCoordinates.of("g", " ", "1", null, null)).isNull();
		assertThat(MavenCoordinates.of("g", "a", "", null, null)).isNull();
		assertThat(MavenCoordinates.of(" g ", "a", "1", "", " ")).isEqualTo(new MavenCoordinates("g", "a", "1", null, null));
	}

	@Test
	public void purlFromCoordinates() {
		assertThat(Purl.maven(SLF4J)).isEqualTo("pkg:maven/org.slf4j/slf4j-api@2.0.17");
		assertThat(Purl.maven(MavenCoordinates.of("g", "a", "1", "sources", "jar")))
			.isEqualTo("pkg:maven/g/a@1?classifier=sources");
	}

	@Test
	@SuppressWarnings("unchecked")
	public void cycloneDxNameAndVersionMatchThePurl() throws Exception {
		Map<String, Object> bom = decode(new CycloneDxSerializer().serialize(model(),
			SbomConfig.of(SbomLevel.SIMPLE, SbomFormat.CYCLONEDX, false, "2026-01-01T00:00:00Z")));
		List<Map<String, Object>> components = (List<Map<String, Object>>) bom.get("components");

		Map<String, Object> slf4j = components.get(0);
		assertThat(slf4j).containsEntry("group", "org.slf4j")
			.containsEntry("name", "slf4j-api")
			.containsEntry("version", "2.0.17")
			.containsEntry("purl", "pkg:maven/org.slf4j/slf4j-api@2.0.17");
		assertThat(properties(slf4j)).containsEntry("osgi:bundle:symbolicName", "slf4j.api")
			.containsEntry("osgi:bundle:version", "2.0.17.v2026");

		Map<String, Object> legacy = components.get(1);
		assertThat(legacy).doesNotContainKey("group")
			.containsEntry("name", "legacy.bundle")
			.containsEntry("version", "0.9.0");
		assertThat(properties(legacy)).containsEntry("osgi:bundle:symbolicName", "legacy.bundle")
			.containsEntry("osgi:identity:matchability", "unverified");
	}

	@Test
	@SuppressWarnings("unchecked")
	public void spdxNameAndVersionMatchThePurl() throws Exception {
		Map<String, Object> doc = decode(new SpdxSerializer().serialize(model(),
			SbomConfig.of(SbomLevel.SIMPLE, SbomFormat.SPDX, false, "2026-01-01T00:00:00Z")));
		List<Map<String, Object>> packages = (List<Map<String, Object>>) doc.get("packages");

		// package 0 is the application
		assertThat(packages.get(1)).containsEntry("name", "slf4j-api")
			.containsEntry("versionInfo", "2.0.17")
			.containsEntry("comment", "OSGi bundle: slf4j.api 2.0.17.v2026.");
		assertThat(packages.get(2)).containsEntry("name", "legacy.bundle")
			.containsEntry("versionInfo", "0.9.0");
		assertThat((String) packages.get(2)
			.get("comment")).contains("OSGi bundle: legacy.bundle 0.9.0.")
				.contains("Identity unverified");
	}

	@SuppressWarnings("unchecked")
	private static Map<String, Object> properties(Map<String, Object> component) {
		List<Map<String, Object>> properties = (List<Map<String, Object>>) component.get("properties");
		return properties.stream()
			.collect(Collectors.toMap(p -> (String) p.get("name"), p -> p.get("value")));
	}

	@SuppressWarnings("unchecked")
	private static Map<String, Object> decode(Resource resource) throws Exception {
		try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
			resource.write(out);
			return CODEC.dec()
				.from(out.toString("UTF-8"))
				.get(Map.class);
		}
	}
}
