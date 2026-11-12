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
package org.gecko.bnd.sbom.serializer;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayOutputStream;
import java.util.Map;
import java.util.UUID;

import org.gecko.bnd.sbom.SbomConfig;
import org.gecko.bnd.sbom.model.SbomComponent;
import org.gecko.bnd.sbom.model.SbomLevel;
import org.gecko.bnd.sbom.model.SbomModel;
import org.gecko.bnd.sbom.model.SbomRefs;
import org.junit.jupiter.api.Test;

import aQute.bnd.osgi.Resource;
import aQute.lib.json.JSONCodec;

/**
 * The serial number / document namespace of a BOM (#12).
 */
public class SerialNumbersTest {

	private static final JSONCodec CODEC = new JSONCodec();

	private static SbomModel model(String version, String sha512) {
		return new SbomModel().setApplicationName("app.bndrun")
			.addComponent(new SbomComponent().setBsn("com.example.foo")
				.setVersion(version)
				.setPurl("pkg:maven/com.example/foo@" + version)
				.setSha512(sha512));
	}

	private static SbomConfig config(String timestamp) {
		return SbomConfig.of(SbomLevel.MEDIUM, SbomFormat.CYCLONEDX, false, timestamp);
	}

	private static UUID serial(SbomModel model, SbomConfig config) {
		return SerialNumbers.of(model, SbomRefs.of(model), config);
	}

	@Test
	public void version5AlgorithmMatchesTheRfcTestVector() {
		// RFC 9562, appendix A.4: DNS namespace, "www.example.com"
		UUID dns = UUID.fromString("6ba7b810-9dad-11d1-80b4-00c04fd430c8");
		assertThat(SerialNumbers.nameBased(dns, "www.example.com"))
			.isEqualTo(UUID.fromString("2ed6657d-e927-568b-95e1-2665a8aea6a2"));
	}

	@Test
	public void sameContentSameSerialRegardlessOfTime() {
		UUID first = serial(model("1.0.0", "aa"), config("2026-01-01T00:00:00Z"));
		UUID second = serial(model("1.0.0", "aa"), config("2026-06-30T12:00:00Z"));

		assertThat(first).isEqualTo(second);
		assertThat(first.version()).isEqualTo(5);
	}

	@Test
	public void changedComponentOrFileChangesTheSerial() {
		UUID base = serial(model("1.0.0", "aa"), config(null));

		assertThat(serial(model("1.0.1", "aa"), config(null))).isNotEqualTo(base);
		assertThat(serial(model("1.0.0", "bb"), config(null))).isNotEqualTo(base);
	}

	@Test
	public void formatAndLevelArePartOfTheIdentity() {
		SbomModel model = model("1.0.0", "aa");
		UUID cdx = serial(model, SbomConfig.of(SbomLevel.MEDIUM, SbomFormat.CYCLONEDX, false, null));

		assertThat(serial(model, SbomConfig.of(SbomLevel.MEDIUM, SbomFormat.SPDX, false, null))).isNotEqualTo(cdx);
		assertThat(serial(model, SbomConfig.of(SbomLevel.SIMPLE, SbomFormat.CYCLONEDX, false, null))).isNotEqualTo(cdx);
	}

	@Test
	public void randomOnRequest() {
		SbomModel model = model("1.0.0", "aa");
		SbomConfig random = config(null).withRandomSerialNumber();

		assertThat(serial(model, random)).isNotEqualTo(serial(model, random));
		assertThat(serial(model, random).version()).isEqualTo(4);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void cycloneDxAndSpdxCarryIt() throws Exception {
		SbomModel model = model("1.0.0", "aa");
		Map<String, Object> bom = decode(new CycloneDxSerializer().serialize(model, config("2026-01-01T00:00:00Z")));
		SbomConfig spdxConfig = SbomConfig.of(SbomLevel.MEDIUM, SbomFormat.SPDX, false, "2026-01-01T00:00:00Z");
		Map<String, Object> doc = decode(new SpdxSerializer().serialize(model, spdxConfig));

		assertThat(bom).containsEntry("serialNumber",
			"urn:uuid:" + serial(model, config("2026-01-01T00:00:00Z")));
		assertThat((String) doc.get("documentNamespace"))
			.isEqualTo("https://spdx.org/spdxdocs/app.bndrun-" + serial(model, spdxConfig));
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
