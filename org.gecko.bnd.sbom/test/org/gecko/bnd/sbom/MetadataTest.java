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
import org.gecko.bnd.sbom.model.SbomTool;
import org.gecko.bnd.sbom.serializer.CycloneDxSerializer;
import org.gecko.bnd.sbom.serializer.SbomFormat;
import org.gecko.bnd.sbom.serializer.SpdxSerializer;
import org.junit.jupiter.api.Test;

import aQute.bnd.osgi.About;
import aQute.bnd.osgi.Processor;
import aQute.bnd.osgi.Resource;
import aQute.lib.json.JSONCodec;

/**
 * Tool and application in the metadata (#15).
 */
public class MetadataTest {

	private static final JSONCodec CODEC = new JSONCodec();

	private static SbomModel model() {
		return new SbomModel().setApplicationName("app.bndrun")
			.setApplicationGroup("org.example")
			.setApplicationVersion("1.2.0")
			.setVcsUrl("https://github.com/example/app")
			.setWebsiteUrl("https://example.org/app")
			.addTool(new SbomTool("org.geckoprojects.bnd", "org.gecko.bnd.sbom", "0.1.0", "Data In Motion",
				"pkg:maven/org.geckoprojects.bnd/org.gecko.bnd.sbom@0.1.0"))
			.addTool(Tools.bnd())
			.addComponent(new SbomComponent().setBsn("c")
				.setVersion("1.0.0"));
	}

	@Test
	@SuppressWarnings("unchecked")
	public void cycloneDxToolsAndApplication() throws Exception {
		Map<String, Object> bom = decode(new CycloneDxSerializer().serialize(model(),
			SbomConfig.of(SbomLevel.SIMPLE, SbomFormat.CYCLONEDX, false, "2026-01-01T00:00:00Z")));
		Map<String, Object> metadata = (Map<String, Object>) bom.get("metadata");

		List<Map<String, Object>> tools = (List<Map<String, Object>>) ((Map<String, Object>) metadata.get("tools"))
			.get("components");
		assertThat(tools).hasSize(2);
		assertThat(tools.get(0)).containsEntry("group", "org.geckoprojects.bnd")
			.containsEntry("name", "org.gecko.bnd.sbom")
			.containsEntry("version", "0.1.0")
			.containsEntry("manufacturer", Map.of("name", "Data In Motion"))
			.containsEntry("purl", "pkg:maven/org.geckoprojects.bnd/org.gecko.bnd.sbom@0.1.0");
		assertThat(tools.get(1)).containsEntry("name", "bnd")
			.containsEntry("version", About.CURRENT.toString());

		Map<String, Object> app = (Map<String, Object>) metadata.get("component");
		assertThat(app).containsEntry("bom-ref", "app.bndrun")
			.containsEntry("group", "org.example")
			.containsEntry("name", "app.bndrun")
			.containsEntry("version", "1.2.0")
			.containsEntry("externalReferences",
				List.of(Map.of("type", "vcs", "url", "https://github.com/example/app"),
					Map.of("type", "website", "url", "https://example.org/app")));
	}

	@Test
	@SuppressWarnings("unchecked")
	public void spdxCreatorsAndApplicationPackage() throws Exception {
		Map<String, Object> doc = decode(new SpdxSerializer().serialize(model(),
			SbomConfig.of(SbomLevel.SIMPLE, SbomFormat.SPDX, false, "2026-01-01T00:00:00Z")));

		Map<String, Object> creationInfo = (Map<String, Object>) doc.get("creationInfo");
		assertThat((List<Object>) creationInfo.get("creators")).containsExactly("Tool: org.gecko.bnd.sbom-0.1.0",
			"Tool: bnd-" + About.CURRENT);

		List<Map<String, Object>> packages = (List<Map<String, Object>>) doc.get("packages");
		assertThat(packages.get(0)).containsEntry("SPDXID", "SPDXRef-app.bndrun")
			.containsEntry("versionInfo", "1.2.0")
			.containsEntry("primaryPackagePurpose", "APPLICATION")
			.containsEntry("downloadLocation", "git+https://github.com/example/app")
			.containsEntry("homepage", "https://example.org/app");

		List<Map<String, Object>> relationships = (List<Map<String, Object>>) doc.get("relationships");
		assertThat(relationships).contains(
			Map.of("spdxElementId", "SPDXRef-DOCUMENT", "relationshipType", "DESCRIBES", "relatedSpdxElement",
				"SPDXRef-app.bndrun"),
			Map.of("spdxElementId", "SPDXRef-app.bndrun", "relationshipType", "CONTAINS", "relatedSpdxElement",
				"SPDXRef-c-1.0.0"));
	}

	@Test
	public void applicationOverridesFromSbomInstruction() {
		Processor reporter = new Processor();
		SbomConfig config = SbomConfig.from(reporter,
			"application.name=Weather, application.group=org.geckoprojects.weather, application.version=2.1.0",
			Map.of());

		assertThat(reporter.isOk()).isTrue();
		assertThat(reporter.getWarnings()).isEmpty();
		assertThat(config.applicationName()).isEqualTo("Weather");
		assertThat(config.applicationGroup()).isEqualTo("org.geckoprojects.weather");
		assertThat(config.applicationVersion()).isEqualTo("2.1.0");
	}

	@Test
	public void scmUrlFromBundleScm() {
		assertThat(SbomModelBuilder.scmUrl(
			"url=https://github.com/eclipse-fennec/emf.osgi, connection=scm:git:https://github.com/eclipse-fennec/emf.osgi.git"))
				.isEqualTo("https://github.com/eclipse-fennec/emf.osgi");
		assertThat(SbomModelBuilder.scmUrl(null)).isNull();
		assertThat(SbomModelBuilder.scmUrl("connection=scm:git:x")).isNull();
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
