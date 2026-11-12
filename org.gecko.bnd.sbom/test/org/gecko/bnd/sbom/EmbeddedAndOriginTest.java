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
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

import org.gecko.bnd.sbom.model.MavenCoordinates;
import org.gecko.bnd.sbom.model.SbomComponent;
import org.gecko.bnd.sbom.model.SbomLevel;
import org.gecko.bnd.sbom.model.SbomModel;
import org.gecko.bnd.sbom.serializer.CycloneDxSerializer;
import org.gecko.bnd.sbom.serializer.SbomFormat;
import org.gecko.bnd.sbom.serializer.SpdxSerializer;
import org.junit.jupiter.api.Test;

import aQute.bnd.osgi.EmbeddedResource;
import aQute.bnd.osgi.Jar;
import aQute.bnd.osgi.Processor;
import aQute.bnd.osgi.Resource;
import aQute.lib.json.JSONCodec;

/**
 * Embedded libraries (#8) and the origin of bundles (#9).
 */
public class EmbeddedAndOriginTest {

	private static final JSONCodec			CODEC	= new JSONCodec();
	private static final MavenCoordinates	OWN		= MavenCoordinates.of("org.geckoprojects.libraries",
		"net.datafaker", "2.5.4-SNAPSHOT", null, null);

	private static void put(Jar jar, String path, String text) {
		jar.putResource(path, new EmbeddedResource(text.getBytes(StandardCharsets.UTF_8), 0L));
	}

	private static String pomProperties(String group, String artifact, String version) {
		return "groupId=" + group + "\nartifactId=" + artifact + "\nversion=" + version + "\n";
	}

	private static byte[] jarBytes(Jar jar) throws Exception {
		try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
			jar.write(out);
			return out.toByteArray();
		}
	}

	private static Jar bundle(String classPath) throws Exception {
		Jar jar = new Jar("bundle");
		Manifest manifest = new Manifest();
		manifest.getMainAttributes()
			.put(Attributes.Name.MANIFEST_VERSION, "1.0");
		manifest.getMainAttributes()
			.putValue("Bundle-SymbolicName", "net.datafaker");
		if (classPath != null) {
			manifest.getMainAttributes()
				.putValue("Bundle-ClassPath", classPath);
		}
		jar.setManifest(manifest);
		return jar;
	}

	@Test
	public void repackagedLibrariesFromPomProperties() throws Exception {
		try (Jar jar = bundle(null)) {
			// the bundle's own entry is not an embedded library
			put(jar, "META-INF/maven/org.geckoprojects.libraries/net.datafaker/pom.properties",
				pomProperties("org.geckoprojects.libraries", "net.datafaker", "2.5.4-SNAPSHOT"));
			put(jar, "OSGI-OPT/src/META-INF/maven/net.datafaker/datafaker/pom.properties",
				pomProperties("net.datafaker", "datafaker", "2.5.4"));
			put(jar, "OSGI-OPT/src/META-INF/maven/net.datafaker/datafaker/pom.xml", """
				<project><licenses><license><name>Apache License, Version 2.0</name></license></licenses></project>
				""");
			put(jar, "META-INF/maven/jakarta.servlet/jakarta.servlet-api/pom.properties",
				pomProperties("jakarta.servlet", "jakarta.servlet-api", "6.1.0"));
			// the same library twice, and an unfiltered template
			put(jar, "META-INF/maven/net.datafaker/datafaker/pom.properties",
				pomProperties("net.datafaker", "datafaker", "2.5.4"));
			put(jar, "META-INF/maven/org.example/template/pom.properties",
				pomProperties("org.example", "template", "${project.version}"));

			List<SbomComponent> embedded = new EmbeddedResolver(null).resolve(jar, OWN, true);

			assertThat(embedded).extracting(SbomComponent::getPurl)
				.containsExactlyInAnyOrder("pkg:maven/net.datafaker/datafaker@2.5.4",
					"pkg:maven/jakarta.servlet/jakarta.servlet-api@6.1.0");
			SbomComponent datafaker = embedded.stream()
				.filter(c -> c.getPurl()
					.contains("datafaker"))
				.findFirst()
				.orElseThrow();
			assertThat(datafaker.getEmbeddedPath()).endsWith("pom.properties");
			assertThat(datafaker.getLicenses()).singleElement()
				.extracting(l -> l.spdxId())
				.isEqualTo("Apache-2.0");
		}
	}

	@Test
	public void jarsOnTheBundleClassPath() throws Exception {
		byte[] identified;
		try (Jar nested = new Jar("parsson")) {
			put(nested, "META-INF/maven/org.eclipse.parsson/parsson/pom.properties",
				pomProperties("org.eclipse.parsson", "parsson", "1.1.7"));
			put(nested, "LICENSE", "Eclipse Public License - v 2.0");
			identified = jarBytes(nested);
		}
		byte[] anonymous;
		try (Jar nested = new Jar("anon")) {
			put(nested, "org/example/A.class", "x");
			anonymous = jarBytes(nested);
		}
		try (Jar jar = bundle(".,lib/parsson.jar,lib/anon.jar,classes/")) {
			jar.putResource("lib/parsson.jar", new EmbeddedResource(identified, 0L));
			jar.putResource("lib/anon.jar", new EmbeddedResource(anonymous, 0L));

			List<SbomComponent> embedded = new EmbeddedResolver(null).resolve(jar, OWN, true);

			assertThat(embedded).hasSize(2);
			assertThat(embedded.get(0)
				.getPurl()).isEqualTo("pkg:maven/org.eclipse.parsson/parsson@1.1.7");
			assertThat(embedded.get(0)
				.getSha512()).hasSize(128);
			assertThat(embedded.get(0)
				.getLicenses()).singleElement()
				.extracting(l -> l.spdxId())
				.isEqualTo("EPL-2.0");
			assertThat(embedded.get(1)
				.getBsn()).isEqualTo("anon.jar");
			assertThat(embedded.get(1)
				.isUnverifiedIdentity()).isTrue();
			assertThat(embedded.get(1)
				.getEmbeddedPath()).isEqualTo("lib/anon.jar");
		}
	}

	@Test
	public void withoutDetailsNoLicensesOrHashes() throws Exception {
		try (Jar jar = bundle(null)) {
			put(jar, "META-INF/maven/jakarta.servlet/jakarta.servlet-api/pom.properties",
				pomProperties("jakarta.servlet", "jakarta.servlet-api", "6.1.0"));
			put(jar, "META-INF/maven/jakarta.servlet/jakarta.servlet-api/pom.xml",
				"<project><licenses><license><name>EPL-2.0</name></license></licenses></project>");

			assertThat(new EmbeddedResolver(null).resolve(jar, OWN, false)).singleElement()
				.satisfies(c -> assertThat(c.getLicenses()).isEmpty());
		}
	}

	@Test
	public void classPackagesIgnoreMetadataAndModuleInfo() throws Exception {
		try (Jar jar = new Jar("x")) {
			put(jar, "org/example/A.class", "");
			put(jar, "org/example/sub/B.class", "");
			put(jar, "org/example/res.txt", "");
			put(jar, "META-INF/versions/11/org/example/C.class", "");
			put(jar, "OSGI-OPT/src/org/other/D.class", "");
			put(jar, "module-info.class", "");

			assertThat(EmbeddedResolver.classPackages(jar)).containsExactly("org.example", "org.example.sub");
		}
	}

	@Test
	public void repositoryKindFromImplementation() {
		assertThat(OriginResolver.kind(new Object())).isEqualTo("object");
	}

	@Test
	public void mavenMappingFromSbomInstruction() {
		Processor reporter = new Processor();
		SbomConfig config = SbomConfig.from(reporter,
			"maven.org.eclipse.uml2.types=org.eclipse.uml2:org.eclipse.uml2.types, "
				+ "maven.org.eclipse.uml2.common=org.eclipse.uml2:org.eclipse.uml2.common:2.5.0-pinned",
			Map.of());

		assertThat(reporter.isOk()).isTrue();
		assertThat(reporter.getWarnings()).isEmpty();
		assertThat(config.mavenMapping("org.eclipse.uml2.types", "2.5.0.v20221116-1811"))
			.isEqualTo(MavenCoordinates.of("org.eclipse.uml2", "org.eclipse.uml2.types", "2.5.0", null, null));
		assertThat(config.mavenMapping("org.eclipse.uml2.common", "2.5.0.v20221116-1811")
			.version()).isEqualTo("2.5.0-pinned");
		assertThat(config.mavenMapping("other", "1.0.0")).isNull();

		SbomConfig.from(reporter, "maven.x=nocolon", Map.of());
		assertThat(reporter.getErrors()).singleElement()
			.asString()
			.contains("groupId:artifactId[:version]");
	}

	private static SbomModel model() {
		SbomComponent bundle = new SbomComponent().setBsn("net.datafaker")
			.setVersion("2.5.4")
			.setPurl("pkg:maven/org.geckoprojects.libraries/net.datafaker@2.5.4")
			.setRepositoryName("EclipseMDT-UML2")
			.setRepositoryKind("p2")
			.setDistributionUrl("https://download.example.org/plugins/net.datafaker_2.5.4.jar");
		SbomComponent library = new SbomComponent().setMaven(MavenCoordinates.of("net.datafaker", "datafaker",
			"2.5.4", null, null))
			.setPurl("pkg:maven/net.datafaker/datafaker@2.5.4")
			.setEmbeddedPath("OSGI-OPT/src/META-INF/maven/net.datafaker/datafaker/pom.properties");
		bundle.addEmbedded(library);
		return new SbomModel().setApplicationName("app")
			.addComponent(bundle)
			.addDependency(bundle, library);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void cycloneDxListsEmbeddedFlat() throws Exception {
		Map<String, Object> bom = decode(new CycloneDxSerializer().serialize(model(),
			SbomConfig.of(SbomLevel.SIMPLE, SbomFormat.CYCLONEDX, false, "2026-01-01T00:00:00Z")));
		List<Map<String, Object>> components = (List<Map<String, Object>>) bom.get("components");

		assertThat(components).hasSize(2);
		Map<String, Object> bundle = components.get(0);
		assertThat(bundle).doesNotContainKey("components")
			.containsEntry("externalReferences", List.of(Map.of("type", "distribution", "url",
				"https://download.example.org/plugins/net.datafaker_2.5.4.jar")));
		assertThat((List<Object>) bundle.get("properties")).contains(
			Map.of("name", "osgi:repository:name", "value", "EclipseMDT-UML2"),
			Map.of("name", "osgi:repository:kind", "value", "p2"));
		assertThat((List<Object>) components.get(1)
			.get("properties")).contains(
				Map.of("name", "osgi:embedded:in", "value", "pkg:maven/org.geckoprojects.libraries/net.datafaker@2.5.4"),
				Map.of("name", "osgi:embedded:source", "value",
					"OSGI-OPT/src/META-INF/maven/net.datafaker/datafaker/pom.properties"));
		assertThat((List<Object>) bom.get("dependencies")).contains(
			Map.of("ref", "pkg:maven/org.geckoprojects.libraries/net.datafaker@2.5.4", "dependsOn",
				List.of("pkg:maven/net.datafaker/datafaker@2.5.4")),
			Map.of("ref", "pkg:maven/net.datafaker/datafaker@2.5.4", "dependsOn", List.of()));
	}

	@Test
	@SuppressWarnings("unchecked")
	public void spdxContainsEmbeddedAndDownloadLocation() throws Exception {
		Map<String, Object> doc = decode(new SpdxSerializer().serialize(model(),
			SbomConfig.of(SbomLevel.SIMPLE, SbomFormat.SPDX, false, "2026-01-01T00:00:00Z")));
		List<Map<String, Object>> packages = (List<Map<String, Object>>) doc.get("packages");

		assertThat(packages).hasSize(3);
		assertThat(packages.get(1)).containsEntry("downloadLocation",
			"https://download.example.org/plugins/net.datafaker_2.5.4.jar");
		assertThat((String) packages.get(1)
			.get("comment")).contains("Repository: EclipseMDT-UML2 (p2).");
		assertThat((List<Object>) doc.get("relationships")).contains(Map.of("spdxElementId",
			"SPDXRef-pkg-maven-org.geckoprojects.libraries-net.datafaker-2.5.4", "relationshipType", "CONTAINS",
			"relatedSpdxElement", "SPDXRef-pkg-maven-net.datafaker-datafaker-2.5.4"));
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
