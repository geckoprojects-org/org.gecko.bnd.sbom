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
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

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

import aQute.bnd.osgi.Resource;
import aQute.lib.json.JSONCodec;

/**
 * Deterministic references (#11): CycloneDX {@code bom-ref} and SPDX {@code SPDXID}.
 */
public class SbomRefsTest {

	private static final JSONCodec CODEC = new JSONCodec();

	private final SbomComponent	maven		= new SbomComponent().setBsn("com.example.foo")
		.setVersion("1.2.3.v2026")
		.setPurl("pkg:maven/com.example/foo@1.2.3");
	private final SbomComponent	unverified	= new SbomComponent().setBsn("legacy.bundle")
		.setVersion("0.9.0")
		.setUnverifiedIdentity(true);

	private SbomModel model() {
		return new SbomModel().setApplicationName("app.bndrun")
			.addComponent(maven)
			.addComponent(unverified);
	}

	@Test
	public void purlOrBsnAtVersion() {
		SbomRefs refs = SbomRefs.of(model());

		assertThat(refs.application()).isEqualTo("app.bndrun");
		assertThat(refs.of(maven)).isEqualTo("pkg:maven/com.example/foo@1.2.3");
		assertThat(refs.of(unverified)).isEqualTo("legacy.bundle@0.9.0");
	}

	@Test
	public void spdxIdsUseOnlyAllowedCharacters() {
		SbomRefs refs = SbomRefs.of(model());

		assertThat(refs.spdxApplication()).isEqualTo("SPDXRef-app.bndrun");
		assertThat(refs.spdxOf(maven)).isEqualTo("SPDXRef-pkg-maven-com.example-foo-1.2.3");
		assertThat(refs.spdxOf(unverified)).isEqualTo("SPDXRef-legacy.bundle-0.9.0");
	}

	@Test
	public void sameModelSameRefs() {
		SbomRefs first = SbomRefs.of(model());
		SbomRefs second = SbomRefs.of(model());

		assertThat(second.of(maven)).isEqualTo(first.of(maven));
		assertThat(second.spdxOf(unverified)).isEqualTo(first.spdxOf(unverified));
	}

	@Test
	public void collisionsGetASuffixInModelOrder() {
		SbomComponent twin = new SbomComponent().setBsn("com.example.foo.twin")
			.setPurl("pkg:maven/com.example/foo@1.2.3");
		SbomModel model = model().addComponent(twin);
		SbomRefs refs = SbomRefs.of(model);

		assertThat(refs.of(maven)).isEqualTo("pkg:maven/com.example/foo@1.2.3");
		assertThat(refs.of(twin)).isEqualTo("pkg:maven/com.example/foo@1.2.3#2");
		assertThat(refs.spdxOf(twin)).isEqualTo("SPDXRef-pkg-maven-com.example-foo-1.2.3-2");
	}

	@Test
	public void spdxDocumentIdIsReserved() {
		SbomComponent document = new SbomComponent().setBsn("DOCUMENT");
		SbomRefs refs = SbomRefs.of(new SbomModel().setApplicationName("app")
			.addComponent(document));

		assertThat(refs.spdxOf(document)).isEqualTo("SPDXRef-DOCUMENT-2");
	}

	@Test
	public void foreignComponentIsRejected() {
		SbomRefs refs = SbomRefs.of(model());

		assertThatIllegalArgumentException().isThrownBy(() -> refs.of(new SbomComponent().setBsn("other")));
	}

	@Test
	@SuppressWarnings("unchecked")
	public void cycloneDxCarriesBomRefs() throws Exception {
		String json = read(new CycloneDxSerializer().serialize(model(),
			SbomConfig.of(SbomLevel.SIMPLE, SbomFormat.CYCLONEDX, false, "2026-01-01T00:00:00Z")));
		Map<String, Object> bom = CODEC.dec()
			.from(json)
			.get(Map.class);

		Map<String, Object> metadata = (Map<String, Object>) bom.get("metadata");
		assertThat((Map<String, Object>) metadata.get("component")).containsEntry("bom-ref", "app.bndrun");

		List<Map<String, Object>> components = (List<Map<String, Object>>) bom.get("components");
		assertThat(components).extracting(c -> c.get("bom-ref"))
			.containsExactly("pkg:maven/com.example/foo@1.2.3", "legacy.bundle@0.9.0");

		List<Map<String, Object>> compositions = (List<Map<String, Object>>) bom.get("compositions");
		assertThat(compositions.get(0)).containsEntry("assemblies", List.of("app.bndrun"));
	}

	@Test
	@SuppressWarnings("unchecked")
	public void spdxUsesTheSameIds() throws Exception {
		String json = read(new SpdxSerializer().serialize(model(),
			SbomConfig.of(SbomLevel.SIMPLE, SbomFormat.SPDX, false, "2026-01-01T00:00:00Z")));
		Map<String, Object> doc = CODEC.dec()
			.from(json)
			.get(Map.class);

		List<Map<String, Object>> packages = (List<Map<String, Object>>) doc.get("packages");
		assertThat(packages).extracting(p -> p.get("SPDXID"))
			.containsExactly("SPDXRef-app.bndrun", "SPDXRef-pkg-maven-com.example-foo-1.2.3",
				"SPDXRef-legacy.bundle-0.9.0");
	}

	private static String read(Resource resource) throws Exception {
		try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
			resource.write(out);
			return out.toString("UTF-8");
		}
	}
}
