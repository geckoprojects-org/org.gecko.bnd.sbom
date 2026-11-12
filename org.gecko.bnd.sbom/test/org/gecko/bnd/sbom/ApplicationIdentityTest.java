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

import org.gecko.bnd.sbom.model.SbomComponent;
import org.gecko.bnd.sbom.model.SbomLevel;
import org.gecko.bnd.sbom.model.SbomModel;
import org.gecko.bnd.sbom.model.SbomRefs;
import org.gecko.bnd.sbom.serializer.CycloneDxSerializer;
import org.gecko.bnd.sbom.serializer.SbomFormat;
import org.gecko.bnd.sbom.serializer.SpdxSerializer;
import org.junit.jupiter.api.Test;

import aQute.bnd.osgi.Processor;
import aQute.bnd.osgi.Resource;
import aQute.lib.json.JSONCodec;

/**
 * The application's PURL and the build's own properties (#10).
 */
public class ApplicationIdentityTest {

	private static final JSONCodec	CODEC	= new JSONCodec();
	private static final String		PURL	= "pkg:oci/weather@sha256%3Aabc?repository_url=registry.example.org";

	private static SbomModel model() {
		return new SbomModel().setApplicationName("weather.bndrun")
			.setApplicationPurl(PURL)
			.addProperty("git:commit", "5a3a59f")
			.addProperty("image", "registry.example.org/weather:1.2")
			.addKnownUnknown("system packages not resolved")
			.addComponent(new SbomComponent().setBsn("c")
				.setVersion("1.0.0"));
	}

	@Test
	public void optionsFromSbomInstruction() {
		Processor reporter = new Processor();
		SbomConfig config = SbomConfig.from(reporter,
			"application.purl=\"" + PURL + "\", property.git:commit=5a3a59f, property.image=\"registry.example.org/weather:1.2\"",
			Map.of());

		assertThat(reporter.getErrors()).isEmpty();
		assertThat(reporter.getWarnings()).isEmpty();
		assertThat(config.applicationPurl()).isEqualTo(PURL);
		assertThat(config.properties()).containsExactly(Map.entry("git:commit", "5a3a59f"),
			Map.entry("image", "registry.example.org/weather:1.2"));
	}

	@Test
	public void invalidPurlAndNamelessPropertyAreErrors() {
		Processor reporter = new Processor();
		SbomConfig config = SbomConfig.from(reporter, "application.purl=weather, property.=x", Map.of());

		assertThat(reporter.getErrors()).hasSize(2);
		assertThat(reporter.getErrors()).anyMatch(e -> e.contains("'weather'") && e.contains("package URL"));
		assertThat(reporter.getErrors()).anyMatch(e -> e.contains("'property.'"));
		assertThat(config.applicationPurl()).isNull();
	}

	@Test
	public void applicationIsReferencedByItsPurl() {
		SbomModel model = model();

		assertThat(SbomRefs.of(model)
			.application()).isEqualTo(PURL);
		assertThat(SbomRefs.of(new SbomModel().setApplicationName("weather.bndrun"))
			.application()).isEqualTo("weather.bndrun");
	}

	@Test
	@SuppressWarnings("unchecked")
	public void cycloneDx() throws Exception {
		Map<String, Object> bom = decode(new CycloneDxSerializer().serialize(model(),
			SbomConfig.of(SbomLevel.SIMPLE, SbomFormat.CYCLONEDX, false, "2026-01-01T00:00:00Z")));
		Map<String, Object> metadata = (Map<String, Object>) bom.get("metadata");

		assertThat((Map<String, Object>) metadata.get("component")).containsEntry("bom-ref", PURL)
			.containsEntry("purl", PURL);
		assertThat((List<Object>) metadata.get("properties")).containsExactly(
			Map.of("name", "git:commit", "value", "5a3a59f"),
			Map.of("name", "image", "value", "registry.example.org/weather:1.2"),
			Map.of("name", "osgi:known-unknown", "value", "system packages not resolved"));
	}

	@Test
	@SuppressWarnings("unchecked")
	public void spdx() throws Exception {
		Map<String, Object> doc = decode(new SpdxSerializer().serialize(model(),
			SbomConfig.of(SbomLevel.SIMPLE, SbomFormat.SPDX, false, "2026-01-01T00:00:00Z")));

		assertThat(doc).containsEntry("comment", "git:commit=5a3a59f\nimage=registry.example.org/weather:1.2");
		Map<String, Object> application = ((List<Map<String, Object>>) doc.get("packages")).get(0);
		assertThat(application).containsEntry("externalRefs", List.of(Map.of("referenceCategory",
			"PACKAGE-MANAGER", "referenceType", "purl", "referenceLocator", PURL)));
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
