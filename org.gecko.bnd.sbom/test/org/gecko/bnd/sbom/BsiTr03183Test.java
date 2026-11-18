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
import static org.assertj.core.api.InstanceOfAssertFactories.STRING;

import java.io.ByteArrayOutputStream;
import java.util.List;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.stream.Collectors;

import org.gecko.bnd.sbom.model.MavenCoordinates;
import org.gecko.bnd.sbom.model.SbomComponent;
import org.gecko.bnd.sbom.model.SbomLevel;
import org.gecko.bnd.sbom.model.SbomLicense;
import org.gecko.bnd.sbom.model.SbomModel;
import org.gecko.bnd.sbom.serializer.CycloneDxSerializer;
import org.gecko.bnd.sbom.serializer.SbomFormat;
import org.junit.jupiter.api.Test;

import aQute.bnd.build.model.EE;
import aQute.bnd.osgi.Processor;
import aQute.bnd.osgi.Resource;
import aQute.lib.json.JSONCodec;

/**
 * BSI TR-03183-2 v2.1.0 in level {@code medium} (#68): the BSI property taxonomy, creators, the
 * Java runtime as logical component with its minimum version, and the conformance check.
 */
public class BsiTr03183Test {

	private static final JSONCodec	CODEC	= new JSONCodec();
	private static final String		TIME	= "2026-01-01T00:00:00Z";

	// --- minimum execution environment (TR §3.2.1) ---

	@Test
	public void minimumEEFromRequireCapability() {
		assertThat(SbomModelBuilder.minimumEE(manifest("Require-Capability",
			"osgi.ee;filter:=\"(&(osgi.ee=JavaSE)(version=11))\"")))
			.isEqualTo(EE.JavaSE_11);
	}

	@Test
	public void minimumEEOfARangeIsItsLowerBound() {
		assertThat(SbomModelBuilder.minimumEE(manifest("Require-Capability",
			"osgi.ee;filter:=\"(&(osgi.ee=JavaSE)(version>=17)(!(version>=22)))\"")))
			.isEqualTo(EE.JavaSE_17);
	}

	@Test
	public void minimumEEFromBundleRequiredExecutionEnvironment() {
		assertThat(SbomModelBuilder.minimumEE(manifest("Bundle-RequiredExecutionEnvironment", "JavaSE-1.8")))
			.isEqualTo(EE.JavaSE_1_8);
	}

	@Test
	public void noExecutionEnvironmentRequired() {
		assertThat(SbomModelBuilder.minimumEE(manifest("Require-Capability",
			"osgi.service;filter:=\"(objectClass=org.example.Foo)\""))).isNull();
		assertThat(SbomModelBuilder.minimumEE(null)).isNull();
	}

	// --- creator (TR §5.2.2) ---

	@Test
	public void creatorEmailFromContactAddress() {
		SbomComponent component = new SbomComponent();
		Manifest manifest = manifest("Bundle-ContactAddress", "Example Org, Some Street 1, security@example.org");
		manifest.getMainAttributes()
			.putValue("Bundle-DocURL", "https://example.org/docs");
		Creators.fromManifest(component, manifest);

		assertThat(component.getCreatorEmail()).isEqualTo("security@example.org");
		assertThat(component.getCreatorUrl()).isNull();
	}

	@Test
	public void creatorUrlFromDocUrlWithoutCredentials() {
		SbomComponent component = new SbomComponent();
		Manifest manifest = manifest("Bundle-DocURL", "https://user:token@example.org/docs?key=secret");
		manifest.getMainAttributes()
			.putValue("Bundle-Vendor", "Example Org");
		Creators.fromManifest(component, manifest);

		assertThat(component.getCreatorUrl()).isEqualTo("https://example.org/docs");
		assertThat(component.getCreatorEmail()).isNull();
	}

	@Test
	public void noCreatorFromVendorAlone() {
		SbomComponent component = new SbomComponent();
		Creators.fromManifest(component, manifest("Bundle-Vendor", "Example Org"));

		assertThat(component.hasCreator()).isFalse();
	}

	// --- CycloneDX output ---

	@Test
	@SuppressWarnings("unchecked")
	public void cycloneDxCarriesTaxonomyPropertiesAndCreators() throws Exception {
		SbomComponent runtime = javaRuntime();
		SbomModel model = new SbomModel().setApplicationName("app")
			.setCreatorEmail("sbom@example.org")
			.addComponent(delivered())
			.addComponent(runtime);

		Map<String, Object> bom = decode(new CycloneDxSerializer().serialize(model, medium(SbomFormat.CYCLONEDX)));

		Map<String, Object> metadata = (Map<String, Object>) bom.get("metadata");
		assertThat(metadata).containsEntry("manufacturer", Map.of("contact", List.of(Map.of("email", "sbom@example.org"))));

		List<Map<String, Object>> components = (List<Map<String, Object>>) bom.get("components");
		Map<String, Object> bundle = components.get(0);
		assertThat(bundle).containsEntry("type", "library")
			.containsEntry("manufacturer", Map.of("url", List.of("https://example.org")));
		assertThat(properties(bundle)).containsEntry(CycloneDxSerializer.BSI_FILENAME, "foo-1.2.3.jar")
			.containsEntry(CycloneDxSerializer.BSI_EXECUTABLE, "executable")
			.containsEntry(CycloneDxSerializer.BSI_ARCHIVE, "archive")
			.containsEntry(CycloneDxSerializer.BSI_STRUCTURED, "structured")
			.doesNotContainKey(CycloneDxSerializer.PROPERTY_VERSION_KIND);

		Map<String, Object> platform = components.get(1);
		assertThat(platform).containsEntry("type", "platform")
			.containsEntry("name", "JavaSE")
			.containsEntry("version", "17.0.0");
		assertThat(properties(platform)).containsEntry(CycloneDxSerializer.PROPERTY_VERSION_KIND, "minimum")
			.containsEntry("osgi:ee", "JavaSE")
			.doesNotContainKey(CycloneDxSerializer.PROPERTY_BSN)
			.doesNotContainKey(CycloneDxSerializer.BSI_EXECUTABLE);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void simpleLevelOutputUnchanged() throws Exception {
		SbomModel model = new SbomModel().setApplicationName("app")
			.addComponent(new SbomComponent().setBsn("foo")
				.setVersion("1.0.0"));

		Map<String, Object> bom = decode(new CycloneDxSerializer().serialize(model,
			SbomConfig.of(SbomLevel.SIMPLE, SbomFormat.CYCLONEDX, false, TIME)));

		assertThat((Map<String, Object>) bom.get("metadata")).doesNotContainKey("manufacturer");
		Map<String, Object> component = ((List<Map<String, Object>>) bom.get("components")).get(0);
		assertThat(component).doesNotContainKey("manufacturer");
		assertThat(properties(component)).doesNotContainKeys(CycloneDxSerializer.BSI_FILENAME,
			CycloneDxSerializer.BSI_EXECUTABLE);
	}

	// --- conformance check ---

	@Test
	public void conformantModelHasNoFindings() {
		SbomModel model = new SbomModel().setApplicationName("app")
			.setCreatorUrl("https://example.org")
			.addComponent(delivered())
			.addComponent(javaRuntime().setCreatorUrl("https://openjdk.org"));

		assertThat(BsiTr03183Validator.validate(model, medium(SbomFormat.CYCLONEDX))).isEmpty();
	}

	@Test
	public void reportsMissingFieldsPerComponent() {
		SbomModel model = new SbomModel().setApplicationName("app")
			.addComponent(new SbomComponent().setBsn("bare")
				.setVersion("1.0.0"))
			.addComponent(javaRuntime());

		List<String> findings = BsiTr03183Validator.validate(model, medium(SbomFormat.CYCLONEDX));

		assertThat(findings).hasSize(3);
		assertThat(findings.get(0)).startsWith("SBOM: no creator");
		assertThat(findings.get(1)).startsWith("bare@1.0.0: missing")
			.contains("creator", "filename", "distribution licence", "SHA-512 hash",
				"executable/archive/structured properties");
		// the Java runtime is outside the scope of delivery: only identified (TR §3.2.4)
		assertThat(findings.get(2)).isEqualTo("JavaSE@17.0.0: missing creator (email address or URL)");
	}

	@Test
	public void shadedLibraryIsOnlyIdentified() {
		SbomComponent bundle = delivered().addEmbedded(new SbomComponent()
			.setMaven(MavenCoordinates.of("com.example", "shaded", "2.0.0", null, null))
			.setPurl("pkg:maven/com.example/shaded@2.0.0")
			.setEmbeddedPath("META-INF/maven/com.example/shaded/pom.properties"));
		SbomModel model = new SbomModel().setApplicationName("app")
			.setCreatorUrl("https://example.org")
			.addComponent(bundle);

		assertThat(BsiTr03183Validator.validate(model, medium(SbomFormat.CYCLONEDX)))
			.containsExactly("pkg:maven/com.example/shaded@2.0.0: missing creator (email address or URL)");
	}

	@Test
	public void spdxAndSimpleLevelAreNotConformant() {
		SbomModel model = new SbomModel().setApplicationName("app")
			.setCreatorUrl("https://example.org");

		assertThat(BsiTr03183Validator.validate(model, medium(SbomFormat.SPDX)))
			.singleElement(STRING)
			.contains("SPDX 3.0.1");
		assertThat(BsiTr03183Validator.validate(model, SbomConfig.of(SbomLevel.SIMPLE, SbomFormat.CYCLONEDX, false, TIME)))
			.singleElement(STRING)
			.contains("level=medium");
	}

	// --- configuration ---

	@Test
	public void validateAndCreatorOptions() {
		Processor reporter = new Processor();
		SbomConfig config = SbomConfig.from(reporter,
			"level=medium, validate=bsi-tr-03183-2, validate.strict=true, creator=sbom@example.org", Map.of());

		assertThat(reporter.getErrors()).isEmpty();
		assertThat(reporter.getWarnings()).isEmpty();
		assertThat(config.validate()).isEqualTo(SbomConfig.VALIDATE_BSI);
		assertThat(config.validateStrict()).isTrue();
		assertThat(config.creator()).isEqualTo("sbom@example.org");
	}

	@Test
	public void invalidValidateAndCreatorAreErrors() {
		Processor reporter = new Processor();
		SbomConfig.from(reporter, "validate=ntia, creator=Example Org", Map.of());

		assertThat(reporter.getErrors()).hasSize(2);
	}

	// --- helpers ---

	private static SbomComponent delivered() {
		return new SbomComponent().setBsn("com.example.foo")
			.setVersion("1.2.3")
			.setMaven(MavenCoordinates.of("com.example", "foo", "1.2.3", null, null))
			.setPurl("pkg:maven/com.example/foo@1.2.3")
			.setFilename("foo-1.2.3.jar")
			.setSha512("abc")
			.addLicense(SbomLicense.spdx("Apache-2.0"))
			.setFileProperties(true, true, true)
			.setCreatorUrl("https://example.org");
	}

	private static SbomComponent javaRuntime() {
		return new SbomComponent().setBsn("JavaSE")
			.setVersion("17.0.0")
			.setLogical(true)
			.setMinimumVersion(true);
	}

	private static SbomConfig medium(SbomFormat format) {
		return SbomConfig.of(SbomLevel.MEDIUM, format, false, TIME);
	}

	private static Manifest manifest(String header, String value) {
		Manifest manifest = new Manifest();
		Attributes main = manifest.getMainAttributes();
		main.put(Attributes.Name.MANIFEST_VERSION, "1.0");
		main.putValue(header, value);
		return manifest;
	}

	@SuppressWarnings("unchecked")
	private static Map<String, Object> properties(Map<String, Object> component) {
		List<Map<String, Object>> properties = (List<Map<String, Object>>) component.getOrDefault("properties",
			List.of());
		return properties.stream()
			.collect(Collectors.toMap(p -> (String) p.get("name"), p -> p.get("value"), (a, b) -> a));
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
