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
import org.gecko.bnd.sbom.serializer.SbomFormat;
import org.gecko.bnd.sbom.serializer.SpdxSerializer;
import aQute.bnd.osgi.Resource;
import aQute.lib.json.JSONCodec;

/**
 * Workspace-free unit test for the SPDX 2.3 serializer.
 */
public class SpdxSerializerTest {

	private static final JSONCodec CODEC = new JSONCodec();

	@Test
	@SuppressWarnings("unchecked")
	public void serializesResolvedComponentsAsSpdxDocument() throws Exception {
		SbomModel model = new SbomModel().setApplicationName("my.app")
			.addComponent(new SbomComponent().setBsn("com.example.foo")
				.setVersion("1.2.3")
				.setPurl("pkg:maven/com.example/foo@1.2.3")
				.setSha512("abc123")
				.addLicense(SbomLicense.spdx("EPL-2.0"))
				.addLicense(SbomLicense.spdx("Apache-2.0")))
			.addComponent(new SbomComponent().setBsn("legacy.obr.bundle")
				.setVersion("0.9.0")
				.addLicense(SbomLicense.named("Acme Proprietary License"))
				.setUnverifiedIdentity(true))
			.addComponent(new SbomComponent().setBsn("no.license.bundle")
				.setVersion("2.0.0"))
			.addKnownUnknown("system packages not resolved");

		SbomConfig config = SbomConfig.of(SbomLevel.MEDIUM, SbomFormat.SPDX, false, "2026-01-01T00:00:00Z");

		Resource resource = new SpdxSerializer().serialize(model, config);
		String json = read(resource);

		Map<String, Object> doc = CODEC.dec()
			.from(json)
			.get(Map.class);

		assertThat(doc).containsEntry("spdxVersion", "SPDX-2.3")
			.containsEntry("dataLicense", "CC0-1.0")
			.containsEntry("SPDXID", "SPDXRef-DOCUMENT")
			.containsEntry("name", "my.app");
		assertThat(json).contains("\"created\":\"2026-01-01T00:00:00Z\"")
			.contains("\"name\":\"com.example.foo\"")
			.contains("\"versionInfo\":\"1.2.3\"")
			.contains("pkg:maven/com.example/foo@1.2.3")
			.contains("\"algorithm\":\"SHA512\"")
			.contains("\"relationshipType\":\"DESCRIBES\"")
			// multiple SPDX ids become a conjunctive expression
			.contains("\"licenseDeclared\":\"EPL-2.0 AND Apache-2.0\"")
			// a free-text license becomes a LicenseRef declared in hasExtractedLicensingInfos
			.contains("\"licenseDeclared\":\"LicenseRef-0\"")
			.contains("hasExtractedLicensingInfos")
			.contains("\"licenseId\":\"LicenseRef-0\"")
			.contains("\"extractedText\":\"Acme Proprietary License\"")
			// a component without any license degrades to NOASSERTION
			.contains("\"licenseDeclared\":\"NOASSERTION\"")
			// unresolvable identity is flagged, not given a fake purl (Q3.b)
			.contains("Identity unverified");
	}

	private static String read(Resource resource) throws Exception {
		try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
			resource.write(out);
			return out.toString("UTF-8");
		}
	}
}
