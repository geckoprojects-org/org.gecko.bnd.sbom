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
import java.io.File;
import java.util.List;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.stream.Collectors;

import org.gecko.bnd.sbom.model.MavenCoordinates;
import org.gecko.bnd.sbom.model.SbomComponent;
import org.gecko.bnd.sbom.model.SbomCreator;
import org.gecko.bnd.sbom.model.SbomLayer;
import org.gecko.bnd.sbom.model.SbomLevel;
import org.gecko.bnd.sbom.model.SbomLicense;
import org.gecko.bnd.sbom.model.SbomModel;
import org.gecko.bnd.sbom.serializer.CycloneDxSerializer;
import org.gecko.bnd.sbom.serializer.SbomFormat;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import aQute.bnd.build.Run;
import aQute.bnd.build.Workspace;
import aQute.bnd.build.model.EE;
import aQute.bnd.osgi.Processor;
import aQute.bnd.osgi.Resource;
import aQute.lib.io.IO;
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
		Manifest manifest = manifest("Bundle-ContactAddress", "Example Org, Some Street 1, security@example.org");
		manifest.getMainAttributes()
			.putValue("Bundle-DocURL", "https://example.org/docs");

		assertThat(Creators.fromManifest(manifest)).isEqualTo(new SbomCreator(null, "security@example.org", null));
	}

	@Test
	public void creatorUrlFromDocUrlWithoutCredentials() {
		Manifest manifest = manifest("Bundle-DocURL", "https://user:token@example.org/docs?key=secret");
		manifest.getMainAttributes()
			.putValue("Bundle-Vendor", "Example Org");

		assertThat(Creators.fromManifest(manifest))
			.isEqualTo(new SbomCreator("Example Org", null, "https://example.org/docs"));
	}

	@Test
	public void vendorAloneIsNoIdentifiedCreator() {
		SbomComponent component = new SbomComponent()
			.setCreator(Creators.fromManifest(manifest("Bundle-Vendor", "Example Org")));

		assertThat(component.getCreator()
			.name()).isEqualTo("Example Org");
		assertThat(component.hasCreator()).isFalse();
	}

	@Test
	public void sbomCreatorFromTheProjectOfTheBndrun(@TempDir File dir) throws Exception {
		Run run = bndrunInProject(dir, "Bundle-Vendor: Example Org\nBundle-ContactAddress: sbom@example.org\n", "");

		SbomModel model = new SbomModelBuilder(run, medium(SbomFormat.CYCLONEDX)).build();

		assertThat(model.getCreator()).isEqualTo(new SbomCreator("Example Org", "sbom@example.org", null));
	}

	@Test
	public void creatorOptionKeepsTheVendorName(@TempDir File dir) throws Exception {
		Run run = bndrunInProject(dir, "Bundle-Vendor: Example Org\n", "-sbom: creator=https://example.org\n");

		SbomModel model = new SbomModelBuilder(run, SbomConfig.from(run, Map.of())).build();

		assertThat(model.getCreator()).isEqualTo(new SbomCreator("Example Org", null, "https://example.org"));
	}

	@Test
	public void noDerivedCreatorAtLevelSimple(@TempDir File dir) throws Exception {
		Run run = bndrunInProject(dir, "Bundle-Vendor: Example Org\nBundle-DocURL: https://example.org\n", "");

		SbomModel model = new SbomModelBuilder(run,
			SbomConfig.of(SbomLevel.SIMPLE, SbomFormat.CYCLONEDX, false, TIME)).build();

		assertThat(model.getCreator()).isNull();
	}

	@Test
	public void javaRuntimeIsTheJavaSEApiWithTheRuneeAsMinimum(@TempDir File dir) throws Exception {
		Run run = bndrunInProject(dir, "", "-runee: JavaSE-21\n");

		SbomComponent javaSE = new SbomModelBuilder(run, medium(SbomFormat.CYCLONEDX)).javaRuntime();

		assertThat(javaSE.getBsn()).isEqualTo("JavaSE");
		assertThat(javaSE.getVersion()).isEqualTo("21.0.0");
		assertThat(javaSE.isLogical()).isTrue();
		assertThat(javaSE.isMinimumVersion()).isTrue();
		assertThat(javaSE.getPurl()).isNull();
		assertThat(javaSE.getDescription()).contains("Java SE platform standard", "not delivered");
		assertThat(javaSE.getCreator()).isEqualTo(SbomCreator.of("Java Community Process", null, "https://jcp.org"));
		assertThat(BsiTr03183Validator.isIdentifiedOnly(javaSE)).isTrue();
		assertThat(javaSE.hasCreator()).isTrue();
	}

	// --- CycloneDX output ---

	@Test
	@SuppressWarnings("unchecked")
	public void cycloneDxCarriesTaxonomyPropertiesAndCreators() throws Exception {
		SbomComponent runtime = javaRuntime();
		SbomModel model = new SbomModel().setApplicationName("app")
			.setCreator(new SbomCreator("Example Org", "sbom@example.org", null))
			.addComponent(delivered())
			.addComponent(runtime);

		Map<String, Object> bom = decode(new CycloneDxSerializer().serialize(model, medium(SbomFormat.CYCLONEDX)));

		Map<String, Object> metadata = (Map<String, Object>) bom.get("metadata");
		Map<String, Object> organization = Map.of("name", "Example Org", "contact",
			List.of(Map.of("email", "sbom@example.org")));
		assertThat(metadata).containsEntry("manufacturer", organization);
		// the application is created by the creator of the SBOM (TR table 9)
		assertThat((Map<String, Object>) metadata.get("component")).containsEntry("manufacturer", organization);

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
			.containsEntry("version", "17.0.0")
			.containsEntry("description", "Java SE API")
			.doesNotContainKey("purl");
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
			.setCreator(SbomCreator.of(null, null, "https://example.org"))
			.addComponent(delivered())
			.addComponent(javaRuntime().setCreator(SbomCreator.of(null, null, "https://openjdk.org")));

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
		assertThat(findings.get(0)).startsWith("SBOM and application: no creator");
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
			.setCreator(SbomCreator.of(null, null, "https://example.org"))
			.addComponent(bundle);

		assertThat(BsiTr03183Validator.validate(model, medium(SbomFormat.CYCLONEDX)))
			.containsExactly("pkg:maven/com.example/shaded@2.0.0: missing creator (email address or URL)");
	}

	@Test
	public void spdxAndSimpleLevelAreNotConformant() {
		SbomModel model = new SbomModel().setApplicationName("app")
			.setCreator(SbomCreator.of(null, null, "https://example.org"));

		assertThat(BsiTr03183Validator.validate(model, medium(SbomFormat.SPDX)))
			.singleElement(STRING)
			.contains("SPDX 3.0.1", "spdx.version=2.3");
		assertThat(BsiTr03183Validator.validate(model, medium(SbomFormat.SPDX).withSpdxVersion("3.0.1"))).isEmpty();
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

	@Test
	@SuppressWarnings("unchecked")
	public void cycloneDxHashOnTheDistributionReference() throws Exception {
		SbomComponent withUrl = new SbomComponent().setBsn("slf4j.api")
			.setVersion("2.0.17")
			.setFilename("slf4j-api-2.0.17.jar")
			.setSha512("abc")
			.setDistributionUrl("https://repo.maven.apache.org/maven2/org/slf4j/slf4j-api/2.0.17/slf4j-api-2.0.17.jar");
		SbomComponent withoutUrl = new SbomComponent().setBsn("example.app")
			.setVersion("1.0.0")
			.setFilename("example.app.jar")
			.setSha512("def");
		SbomModel model = new SbomModel().setApplicationName("app")
			.addComponent(withUrl)
			.addComponent(withoutUrl)
			.addComponent(new SbomComponent().setBsn("JavaSE")
				.setVersion("21.0.0")
				.setLogical(true));

		List<Map<String, Object>> components = (List<Map<String, Object>>) decode(
			new CycloneDxSerializer().serialize(model, medium(SbomFormat.CYCLONEDX))).get("components");

		// TR table 9: the hash of the deployable component on its distribution reference
		assertThat((List<Object>) components.get(0)
			.get("externalReferences")).containsExactly(Map.of("type", "distribution", "url",
				withUrl.getDistributionUrl(), "hashes", List.of(Map.of("alg", "SHA-512", "content", "abc"))));
		// without a download URL the reference names the file
		assertThat((List<Object>) components.get(1)
			.get("externalReferences")).containsExactly(Map.of("type", "distribution", "url", "example.app.jar",
				"hashes", List.of(Map.of("alg", "SHA-512", "content", "def"))));
		// still in "hashes", too
		assertThat(components.get(1)).containsKey("hashes");
		// no file, no distribution reference
		assertThat(components.get(2)).doesNotContainKey("externalReferences");
	}

	// --- scope of delivery of the framework ---

	@Test
	public void frameworkIsDeliveredByDefault() {
		Processor reporter = new Processor();
		SbomConfig config = SbomConfig.from(reporter, "level=medium", Map.of());

		assertThat(reporter.getErrors()).isEmpty();
		assertThat(config.frameworkProvided()).isFalse();
	}

	@Test
	public void frameworkProvidedOption() {
		Processor reporter = new Processor();
		SbomConfig config = SbomConfig.from(reporter, "level=medium, framework=provided", Map.of());

		assertThat(reporter.getErrors()).isEmpty();
		assertThat(config.frameworkProvided()).isTrue();
		assertThat(config.withFrameworkProvided(false)
			.frameworkProvided()).isFalse();
	}

	@Test
	public void invalidFrameworkIsAnError() {
		Processor reporter = new Processor();
		SbomConfig.from(reporter, "framework=shipped", Map.of());

		assertThat(reporter.getErrors()).hasSize(1);
	}

	@Test
	public void providedFrameworkIsOnlyIdentified() {
		SbomComponent framework = providedFramework();
		SbomModel model = new SbomModel().setCreator(SbomCreator.of("Example Org", "sbom@example.org", null))
			.addComponent(framework);

		assertThat(BsiTr03183Validator.isIdentifiedOnly(framework)).isTrue();
		assertThat(BsiTr03183Validator.validate(model, medium(SbomFormat.CYCLONEDX))).isEmpty();
	}

	@Test
	@SuppressWarnings("unchecked")
	public void cycloneDxMarksAProvidedFramework() throws Exception {
		SbomModel model = new SbomModel().setApplicationName("app")
			.addComponent(providedFramework());

		Map<String, Object> bom = decode(new CycloneDxSerializer().serialize(model, medium(SbomFormat.CYCLONEDX)));
		Map<String, Object> component = ((List<Map<String, Object>>) bom.get("components")).get(0);
		Map<String, Object> properties = ((List<Map<String, Object>>) component.get("properties")).stream()
			.collect(Collectors.toMap(p -> (String) p.get("name"), p -> p.get("value")));

		assertThat(component).doesNotContainKey("hashes");
		assertThat(properties).containsEntry(CycloneDxSerializer.PROPERTY_DELIVERY, "provided")
			.containsEntry(CycloneDxSerializer.PROPERTY_VERSION_KIND, "minimum")
			.containsEntry("osgi:layer", "runfw")
			.doesNotContainKey(CycloneDxSerializer.BSI_FILENAME);
	}

	private static SbomComponent providedFramework() {
		return new SbomComponent().setBsn("org.apache.felix.framework")
			.setVersion("7.0.5")
			.setLayer(SbomLayer.RUNFW)
			.setProvided(true)
			.setMinimumVersion(true)
			.setCreator(SbomCreator.of("The Apache Software Foundation", null, "https://felix.apache.org"));
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
			.setCreator(SbomCreator.of(null, null, "https://example.org"));
	}

	private static SbomComponent javaRuntime() {
		return new SbomComponent().setBsn("JavaSE")
			.setVersion("17.0.0")
			.setLogical(true)
			.setMinimumVersion(true)
			.setDescription("Java SE API");
	}

	/**
	 * A workspace with one project {@code proj} whose {@code bnd.bnd} holds {@code projectBnd},
	 * and in it {@code app.bndrun} with {@code bndrun}.
	 */
	private static Run bndrunInProject(File dir, String projectBnd, String bndrun) throws Exception {
		File cnf = new File(dir, "cnf");
		cnf.mkdirs();
		IO.store("", new File(cnf, "build.bnd"));
		File proj = new File(dir, "proj");
		proj.mkdirs();
		IO.store(projectBnd, new File(proj, "bnd.bnd"));
		File file = new File(proj, "app.bndrun");
		IO.store(bndrun, file);
		Workspace workspace = new Workspace(dir);
		return Run.createRun(workspace, file);
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
