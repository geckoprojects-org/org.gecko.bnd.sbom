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
import org.gecko.bnd.sbom.model.SbomCreator;
import org.gecko.bnd.sbom.model.SbomLevel;
import org.gecko.bnd.sbom.model.SbomLicense;
import org.gecko.bnd.sbom.model.SbomModel;
import org.gecko.bnd.sbom.model.SbomTool;
import org.gecko.bnd.sbom.serializer.SbomFormat;
import org.gecko.bnd.sbom.serializer.SbomSerializers;
import org.gecko.bnd.sbom.serializer.Spdx3Serializer;
import org.gecko.bnd.sbom.serializer.SpdxSerializer;
import org.junit.jupiter.api.Test;

import aQute.bnd.osgi.Processor;
import aQute.bnd.osgi.Resource;
import aQute.lib.json.JSONCodec;

/**
 * SPDX 3.0.1 JSON-LD, mapped as BSI TR-03183-2 v2.1.0 tables 8–12 describe it.
 */
public class Spdx3SerializerTest {

	private static final JSONCodec	CODEC	= new JSONCodec();
	private static final String		TIME	= "2026-01-01T00:00:00Z";

	private static SbomConfig spdx3() {
		return SbomConfig.of(SbomLevel.MEDIUM, SbomFormat.SPDX, false, TIME)
			.withSpdxVersion("3.0.1");
	}

	private static SbomModel model() {
		SbomComponent slf4j = new SbomComponent().setBsn("slf4j.api")
			.setVersion("2.0.17")
			.setMaven(new MavenCoordinates("org.slf4j", "slf4j-api", "2.0.17", null, null))
			.setPurl("pkg:maven/org.slf4j/slf4j-api@2.0.17")
			.setFilename("slf4j-api-2.0.17.jar")
			.setSha512("abc123")
			.setFileProperties(true, true, true)
			.setCreator(SbomCreator.of("SLF4J.ORG", null, "http://www.slf4j.org"))
			.addLicense(SbomLicense.spdx("MIT"));
		SbomComponent bundle = new SbomComponent().setBsn("example.app")
			.setVersion("1.0.0")
			.setFilename("example.app.jar")
			.setSha512("def456")
			.setFileProperties(true, true, false)
			.setCreator(SbomCreator.of("Example Org", "sbom@example.org", null))
			.addLicense(SbomLicense.named("Vendor License"));
		SbomComponent javaSE = new SbomComponent().setBsn("JavaSE")
			.setVersion("21.0.0")
			.setLogical(true)
			.setProvided(true)
			.setMinimumVersion(true);
		return new SbomModel().setApplicationName("app")
			.setApplicationVersion("1.0.0")
			.setCreator(SbomCreator.of("Example Org", "sbom@example.org", null))
			.addTool(new SbomTool("biz.aQute.bnd", "bnd", "7.1.0", null, null))
			.addComponent(bundle)
			.addComponent(slf4j)
			.addComponent(javaSE)
			.addDependency(bundle, slf4j)
			.addApplicationDependency(bundle);
	}

	@Test
	public void selectedBySpdxVersion() {
		assertThat(SbomSerializers.forConfig(spdx3())).isInstanceOf(Spdx3Serializer.class);
		assertThat(SbomSerializers.forConfig(SbomConfig.of(SbomLevel.MEDIUM, SbomFormat.SPDX, false, TIME)))
			.isInstanceOf(SpdxSerializer.class);
	}

	@Test
	public void spdxVersionOption() {
		Processor reporter = new Processor();
		SbomConfig config = SbomConfig.from(reporter, "format=spdx, spdx.version=3.0.1", Map.of());
		assertThat(reporter.getErrors()).isEmpty();
		assertThat(config.spdxVersion()).isEqualTo("3.0.1");
		assertThat(config.isSpdx3()).isTrue();

		SbomConfig.from(reporter, "spdx.version=3.0", Map.of());
		assertThat(reporter.getErrors()).hasSize(1);

		assertThat(SbomConfig.from(new Processor(), "format=spdx", Map.of())
			.spdxVersion()).isEqualTo("2.3");
	}

	@Test
	public void documentSbomAndCreationInfo() throws Exception {
		List<Map<String, Object>> graph = graph(model());

		assertThat(graph.get(0)).containsEntry("type", "CreationInfo")
			.containsEntry("@id", "_:creationinfo")
			.containsEntry("specVersion", "3.0.1")
			.containsEntry("created", TIME);
		Map<String, Object> document = only(graph, "SpdxDocument");
		Map<String, Object> sbom = only(graph, "software_Sbom");
		Map<String, Object> application = byName(graph, "app");
		assertThat(document.get("rootElement")).isEqualTo(List.of(sbom.get("spdxId")));
		assertThat(sbom.get("rootElement")).isEqualTo(List.of(application.get("spdxId")));
		assertThat(application).containsEntry("software_primaryPurpose", "application")
			.containsEntry("software_packageVersion", "1.0.0");
		// every element id is an IRI under the document's namespace
		String namespace = ((String) document.get("spdxId")).replace("SPDXRef-DOCUMENT", "");
		assertThat(graph.stream()
			.filter(e -> e.containsKey("spdxId"))
			.map(e -> (String) e.get("spdxId"))).allMatch(id -> id.startsWith(namespace));
	}

	@Test
	@SuppressWarnings("unchecked")
	public void sbomCreatorAndTools() throws Exception {
		List<Map<String, Object>> graph = graph(model());
		Map<String, Object> creationInfo = graph.get(0);

		Map<String, Object> creator = byId(graph, ((List<String>) creationInfo.get("createdBy")).get(0));
		assertThat(creator).containsEntry("type", "Organization")
			.containsEntry("name", "Example Org");
		assertThat((List<Map<String, Object>>) creator.get("externalIdentifier"))
			.containsExactly(Map.of("type", "ExternalIdentifier", "externalIdentifierType", "email", "identifier",
				"sbom@example.org"));
		assertThat(byId(graph, ((List<String>) creationInfo.get("createdUsing")).get(0))).containsEntry("type", "Tool")
			.containsEntry("name", "bnd-7.1.0");
		// TR table 9: the application's creator is the SBOM's
		assertThat(byName(graph, "app").get("originatedBy")).isEqualTo(creationInfo.get("createdBy"));
	}

	@Test
	@SuppressWarnings("unchecked")
	public void componentCreatorUrlIsOfTypeOther() throws Exception {
		List<Map<String, Object>> graph = graph(model());
		Map<String, Object> slf4j = byName(graph, "slf4j-api");

		Map<String, Object> creator = byId(graph, ((List<String>) slf4j.get("originatedBy")).get(0));
		assertThat((List<Map<String, Object>>) creator.get("externalIdentifier"))
			.containsExactly(Map.of("type", "ExternalIdentifier", "externalIdentifierType", "other", "identifier",
				"http://www.slf4j.org"));
		assertThat(slf4j).containsEntry("software_packageVersion", "2.0.17")
			.containsEntry("software_packageUrl", "pkg:maven/org.slf4j/slf4j-api@2.0.17");
		assertThat((List<Map<String, Object>>) slf4j.get("externalIdentifier"))
			.containsExactly(Map.of("type", "ExternalIdentifier", "externalIdentifierType", "packageUrl", "identifier",
				"pkg:maven/org.slf4j/slf4j-api@2.0.17"));
	}

	@Test
	@SuppressWarnings("unchecked")
	public void distributionArtifactCarriesFilenameHashAndFileProperties() throws Exception {
		List<Map<String, Object>> graph = graph(model());
		Map<String, Object> slf4j = byName(graph, "slf4j-api");

		Map<String, Object> artifact = relationship(graph, slf4j, "hasDistributionArtifact");
		assertThat(artifact).containsEntry("completeness", "complete");
		Map<String, Object> file = byId(graph, ((List<String>) artifact.get("to")).get(0));
		assertThat(file).containsEntry("type", "software_File")
			.containsEntry("name", "slf4j-api-2.0.17.jar")
			.containsEntry("comment", Spdx3Serializer.BSI_PURPOSE_COMMENT);
		assertThat((List<Object>) file.get("verifiedUsing"))
			.containsExactly(Map.of("type", "Hash", "algorithm", "sha512", "hashValue", "abc123"));
		assertThat((List<Object>) file.get("software_additionalPurpose")).containsExactly("executable", "archive",
			"container");

		// not structured: firmware instead of container
		Map<String, Object> bundleFile = byId(graph,
			((List<String>) relationship(graph, byName(graph, "example.app"), "hasDistributionArtifact").get("to"))
				.get(0));
		assertThat((List<Object>) bundleFile.get("software_additionalPurpose")).containsExactly("executable", "archive",
			"firmware");
	}

	@Test
	@SuppressWarnings("unchecked")
	public void licencesConcludedAndDeclared() throws Exception {
		List<Map<String, Object>> graph = graph(model());
		Map<String, Object> slf4j = byName(graph, "slf4j-api");

		Map<String, Object> concluded = relationship(graph, slf4j, "hasConcludedLicense");
		Map<String, Object> declared = relationship(graph, slf4j, "hasDeclaredLicense");
		assertThat(concluded.get("to")).isEqualTo(declared.get("to"));
		assertThat(byId(graph, ((List<String>) concluded.get("to")).get(0)))
			.containsEntry("type", "simplelicensing_LicenseExpression")
			.containsEntry("simplelicensing_licenseExpression", "MIT");

		// free text: a LicenseRef, declared as licensing text and mapped in the expression
		Map<String, Object> vendor = byId(graph,
			((List<String>) relationship(graph, byName(graph, "example.app"), "hasConcludedLicense").get("to"))
				.get(0));
		assertThat(vendor).containsEntry("simplelicensing_licenseExpression", "LicenseRef-0");
		Map<String, Object> entry = ((List<Map<String, Object>>) vendor.get("simplelicensing_customIdToUri")).get(0);
		assertThat(entry).containsEntry("key", "LicenseRef-0");
		assertThat(byId(graph, (String) entry.get("value"))).containsEntry("type", "simplelicensing_SimpleLicensingText")
			.containsEntry("simplelicensing_licenseText", "Vendor License");
	}

	@Test
	@SuppressWarnings("unchecked")
	public void containsAndDependsOnWithCompleteness() throws Exception {
		List<Map<String, Object>> graph = graph(model());
		Map<String, Object> application = byName(graph, "app");
		Map<String, Object> bundle = byName(graph, "example.app");

		Map<String, Object> contains = relationship(graph, application, "contains");
		assertThat((List<Object>) contains.get("to")).hasSize(3);
		assertThat(contains).containsEntry("completeness", "complete");
		Map<String, Object> dependsOn = relationship(graph, bundle, "dependsOn");
		assertThat((List<Object>) dependsOn.get("to")).containsExactly(byName(graph, "slf4j-api").get("spdxId"));
		// the model declares its dependencies incomplete
		assertThat(dependsOn).containsEntry("completeness", "incomplete");
		assertThat(relationship(graph, application, "dependsOn")
			.get("to")).isEqualTo(List.of(bundle.get("spdxId")));
	}

	@Test
	public void logicalComponentIsAPlatformWithoutFile() throws Exception {
		List<Map<String, Object>> graph = graph(model());
		Map<String, Object> javaSE = byName(graph, "JavaSE");

		assertThat(javaSE).containsEntry("software_primaryPurpose", "platform");
		assertThat((String) javaSE.get("comment")).contains("Not delivered", "minimum");
		assertThat(graph.stream()
			.filter(e -> "Relationship".equals(e.get("type")) && javaSE.get("spdxId")
				.equals(e.get("from")))).isEmpty();
	}

	@Test
	public void sameModelSameDocument() throws Exception {
		assertThat(read(new Spdx3Serializer().serialize(model(), spdx3())))
			.isEqualTo(read(new Spdx3Serializer().serialize(model(), spdx3())));
	}

	@Test
	public void spdx3SatisfiesTheBsiFormatRequirement() {
		SbomModel model = new SbomModel().setApplicationName("app")
			.setCreator(SbomCreator.of(null, null, "https://example.org"));

		assertThat(BsiTr03183Validator.validate(model, spdx3())).isEmpty();
	}

	// --- helpers ---

	@SuppressWarnings("unchecked")
	private static List<Map<String, Object>> graph(SbomModel model) throws Exception {
		Map<String, Object> root = CODEC.dec()
			.from(read(new Spdx3Serializer().serialize(model, spdx3())))
			.get(Map.class);
		assertThat(root).containsEntry("@context", "https://spdx.org/rdf/3.0.1/spdx-context.jsonld");
		return (List<Map<String, Object>>) root.get("@graph");
	}

	private static Map<String, Object> only(List<Map<String, Object>> graph, String type) {
		List<Map<String, Object>> found = graph.stream()
			.filter(e -> type.equals(e.get("type")))
			.collect(Collectors.toList());
		assertThat(found).hasSize(1);
		return found.get(0);
	}

	private static Map<String, Object> byName(List<Map<String, Object>> graph, String name) {
		return graph.stream()
			.filter(e -> "software_Package".equals(e.get("type")) && name.equals(e.get("name")))
			.findFirst()
			.orElseThrow();
	}

	private static Map<String, Object> byId(List<Map<String, Object>> graph, String id) {
		return graph.stream()
			.filter(e -> id.equals(e.get("spdxId")))
			.findFirst()
			.orElseThrow();
	}

	private static Map<String, Object> relationship(List<Map<String, Object>> graph, Map<String, Object> from,
		String type) {
		return graph.stream()
			.filter(e -> "Relationship".equals(e.get("type")) && from.get("spdxId")
				.equals(e.get("from")) && type.equals(e.get("relationshipType")))
			.findFirst()
			.orElseThrow();
	}

	private static String read(Resource resource) throws Exception {
		try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
			resource.write(out);
			return out.toString("UTF-8");
		}
	}
}
