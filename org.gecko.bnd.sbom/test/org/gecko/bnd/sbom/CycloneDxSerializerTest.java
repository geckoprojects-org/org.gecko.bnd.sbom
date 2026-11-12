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
import java.util.Map;

import org.junit.jupiter.api.Test;

import org.gecko.bnd.sbom.SbomConfig;
import org.gecko.bnd.sbom.model.SbomComponent;
import org.gecko.bnd.sbom.model.SbomLevel;
import org.gecko.bnd.sbom.model.SbomLicense;
import org.gecko.bnd.sbom.model.SbomModel;
import org.gecko.bnd.sbom.serializer.CycloneDxSerializer;
import org.gecko.bnd.sbom.serializer.SbomFormat;
import aQute.bnd.osgi.Resource;
import aQute.lib.json.JSONCodec;

/**
 * Workspace-free unit test for the CycloneDX serializer: builds a model directly, serializes,
 * and asserts the resulting BOM structure.
 */
public class CycloneDxSerializerTest {

	private static final JSONCodec CODEC = new JSONCodec();

	@Test
	@SuppressWarnings("unchecked")
	public void serializesResolvedComponentsAndKnownUnknowns() throws Exception {
		SbomModel model = new SbomModel().setApplicationName("my.app")
			.addComponent(new SbomComponent().setBsn("com.example.foo")
				.setVersion("1.2.3")
				.setPurl("pkg:maven/com.example/foo@1.2.3")
				.setSha512("abc123")
				.addLicense(SbomLicense.spdx("Apache-2.0"))
				.addLicense(SbomLicense.spdx("EPL-2.0")))
			.addComponent(new SbomComponent().setBsn("legacy.obr.bundle")
				.setVersion("0.9.0")
				.addLicense(SbomLicense.named("see https://example.com/LICENSE"))
				.setUnverifiedIdentity(true))
			.addKnownUnknown("Framework-level dependencies (A2.2) not yet captured");

		// timestamp pinned so the test is reproducible
		SbomConfig config = SbomConfig.of(SbomLevel.MEDIUM, SbomFormat.CYCLONEDX, false, "2026-01-01T00:00:00Z");

		Resource resource = new CycloneDxSerializer().serialize(model, config);
		String json = read(resource);

		Map<String, Object> bom = CODEC.dec()
			.from(json)
			.get(Map.class);

		assertThat(bom).containsEntry("bomFormat", "CycloneDX")
			.containsEntry("specVersion", "1.6");
		assertThat(json).contains("\"name\":\"my.app\"")
			.contains("pkg:maven/com.example/foo@1.2.3")
			.contains("Apache-2.0")
			// multiple licenses become multiple license entries
			.contains("EPL-2.0")
			.contains("\"name\":\"see https://example.com/LICENSE\"")
			.contains("SHA-512")
			.contains("2026-01-01T00:00:00Z")
			// unresolvable identity is flagged honestly, not given a fake PURL (Q3.b)
			.contains("osgi:identity:matchability")
			// completeness caveat is emitted (A2.5/Q4)
			.contains("\"aggregate\":\"incomplete\"")
			.contains("osgi:known-unknown");
	}

	@Test
	public void unverifiedComponentHasNoPurl() throws Exception {
		SbomModel model = new SbomModel().setApplicationName("app")
			.addComponent(new SbomComponent().setBsn("no.maven.coords")
				.setVersion("1.0.0")
				.setUnverifiedIdentity(true));

		SbomConfig config = SbomConfig.of(SbomLevel.SIMPLE, SbomFormat.CYCLONEDX, false, "2026-01-01T00:00:00Z");

		String json = read(new CycloneDxSerializer().serialize(model, config));

		assertThat(json).doesNotContain("\"purl\"");
	}

	private static String read(Resource resource) throws Exception {
		try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
			resource.write(out);
			return out.toString("UTF-8");
		}
	}
}
