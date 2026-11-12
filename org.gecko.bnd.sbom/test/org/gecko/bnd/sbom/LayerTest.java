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
import org.gecko.bnd.sbom.model.SbomLayer;
import org.gecko.bnd.sbom.model.SbomLevel;
import org.gecko.bnd.sbom.model.SbomModel;
import org.gecko.bnd.sbom.serializer.CycloneDxSerializer;
import org.gecko.bnd.sbom.serializer.SbomFormat;
import org.gecko.bnd.sbom.serializer.SpdxSerializer;
import org.junit.jupiter.api.Test;

import aQute.bnd.osgi.Resource;
import aQute.lib.json.JSONCodec;

/**
 * The layer of a component in the runtime: installed bundle, framework or framework class path.
 */
public class LayerTest {

	private static final JSONCodec CODEC = new JSONCodec();

	private static SbomModel model() {
		return new SbomModel().setApplicationName("app")
			.addComponent(new SbomComponent().setBsn("bundle")
				.setVersion("1.0.0")
				.setLayer(SbomLayer.RUNBUNDLE))
			.addComponent(new SbomComponent().setBsn("org.apache.felix.framework")
				.setVersion("7.0.5")
				.setLayer(SbomLayer.RUNFW))
			.addComponent(new SbomComponent().setBsn("slf4j.api")
				.setVersion("2.0.17")
				.setLayer(SbomLayer.RUNPATH));
	}

	@Test
	@SuppressWarnings("unchecked")
	public void cycloneDxLayerProperty() throws Exception {
		Map<String, Object> bom = decode(new CycloneDxSerializer().serialize(model(),
			SbomConfig.of(SbomLevel.SIMPLE, SbomFormat.CYCLONEDX, false, "2026-01-01T00:00:00Z")));
		List<Map<String, Object>> components = (List<Map<String, Object>>) bom.get("components");

		assertThat(components).extracting(c -> ((List<Map<String, Object>>) c.get("properties")).stream()
			.filter(p -> "osgi:layer".equals(p.get("name")))
			.map(p -> p.get("value"))
			.findFirst()
			.orElse(null))
			.containsExactly("runbundle", "runfw", "runpath");
	}

	@Test
	@SuppressWarnings("unchecked")
	public void spdxLayerInComment() throws Exception {
		Map<String, Object> doc = decode(new SpdxSerializer().serialize(model(),
			SbomConfig.of(SbomLevel.SIMPLE, SbomFormat.SPDX, false, "2026-01-01T00:00:00Z")));
		List<Map<String, Object>> packages = (List<Map<String, Object>>) doc.get("packages");

		assertThat((String) packages.get(3)
			.get("comment")).contains("Layer: runpath.");
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
