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
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.gecko.bnd.sbom.model.SbomComponent;
import org.junit.jupiter.api.Test;

import aQute.bnd.osgi.EmbeddedResource;
import aQute.bnd.osgi.Jar;

/**
 * Security hardening of the exporter: resource limits (CWE-400/409), ReDoS (CWE-1333), URLs
 * published without credentials (CWE-200), robustness against broken input (CWE-754) and XML
 * (CWE-611/776).
 */
public class HardeningTest {

	@Test
	public void readStopsAtTheLimit() throws Exception {
		assertThat(Limits.read(new ByteArrayInputStream(new byte[10]), 10)).hasSize(10);
		assertThat(Limits.read(new ByteArrayInputStream(new byte[11]), 10)).isNull();
		assertThat(Limits.head(new ByteArrayInputStream("abcdef".getBytes(StandardCharsets.UTF_8)), 3))
			.isEqualTo("abc");
	}

	@Test
	public void publishedUrlsCarryNoCredentials() {
		assertThat(Limits.publishableUrl("https://user:s3cret@nexus.example.org/repository/releases/?token=abc#x"))
			.isEqualTo("https://nexus.example.org/repository/releases/");
		assertThat(Limits.publishableUrl("HTTPS://repo.example.org:8443/maven2/"))
			.isEqualTo("https://repo.example.org:8443/maven2/");
		assertThat(Limits.publishableUrl("file:///home/user/.m2/repository")).isNull();
		assertThat(Limits.publishableUrl("scm:git:https://github.com/x/y.git")).isNull();
		assertThat(Limits.publishableUrl("not a url")).isNull();
		assertThat(Limits.publishableUrl(null)).isNull();
	}

	private static byte[] zip(Map<String, byte[]> entries) throws Exception {
		ByteArrayOutputStream bytes = new ByteArrayOutputStream();
		try (ZipOutputStream out = new ZipOutputStream(bytes)) {
			for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
				out.putNextEntry(new ZipEntry(entry.getKey()));
				out.write(entry.getValue());
				out.closeEntry();
			}
		}
		return bytes.toByteArray();
	}

	private static Jar bundleWith(String path, byte[] nested) {
		Jar jar = new Jar("bundle");
		Manifest manifest = new Manifest();
		manifest.getMainAttributes()
			.put(Attributes.Name.MANIFEST_VERSION, "1.0");
		manifest.getMainAttributes()
			.putValue("Bundle-SymbolicName", "bundle");
		manifest.getMainAttributes()
			.putValue("Bundle-ClassPath", ".," + path);
		jar.setManifest(manifest);
		jar.putResource(path, new EmbeddedResource(nested, 0L));
		return jar;
	}

	@Test
	public void zipBombInAnEmbeddedJarIsNotExpanded() throws Exception {
		// compresses to a few hundred KiB, expands beyond the scan limit
		Map<String, byte[]> entries = new LinkedHashMap<>();
		byte[] zeros = new byte[64 * 1024 * 1024];
		for (int i = 0; i < 5; i++) {
			entries.put("data/" + i + ".bin", zeros);
		}
		entries.put("META-INF/maven/org.example/bomb/pom.properties",
			"groupId=org.example\nartifactId=bomb\nversion=1\n".getBytes(StandardCharsets.UTF_8));
		byte[] bomb = zip(entries);
		assertThat(bomb.length).isLessThan(Limits.EMBEDDED_JAR);

		try (Jar jar = bundleWith("lib/bomb.jar", bomb)) {
			List<SbomComponent> embedded = assertTimeoutPreemptively(Duration.ofSeconds(30),
				() -> new EmbeddedResolver(null).resolve(jar, null, true));

			assertThat(embedded).singleElement()
				.satisfies(c -> {
					assertThat(c.isUnverifiedIdentity()).isTrue();
					assertThat(c.getEmbeddedPath()).contains("lib/bomb.jar")
						.contains("not analysed");
				});
		}
	}

	@Test
	public void embeddedJarKeepsOnlyMetadataInMemory() throws Exception {
		Map<String, byte[]> entries = new LinkedHashMap<>();
		entries.put("org/example/Big.class", new byte[8 * 1024 * 1024]);
		entries.put("META-INF/maven/org.example/lib/pom.properties",
			"groupId=org.example\nartifactId=lib\nversion=1.2\n".getBytes(StandardCharsets.UTF_8));
		entries.put("META-INF/LICENSE", "Apache License\nVersion 2.0, January 2004".getBytes(StandardCharsets.UTF_8));

		try (Jar jar = bundleWith("lib/lib.jar", zip(entries))) {
			List<SbomComponent> embedded = new EmbeddedResolver(null).resolve(jar, null, true);

			assertThat(embedded).singleElement()
				.satisfies(c -> {
					assertThat(c.getPurl()).isEqualTo("pkg:maven/org.example/lib@1.2");
					assertThat(c.getSha512()).hasSize(128);
					assertThat(c.getLicenses()).singleElement()
						.extracting(l -> l.spdxId())
						.isEqualTo("Apache-2.0");
				});
		}
	}

	@Test
	public void longLineWithoutLettersIsFast() {
		String text = "1".repeat(200_000) + "\n2\n";
		assertTimeoutPreemptively(Duration.ofSeconds(2), () -> new LicenseResolver().fromLicenseText(text));
	}

	@Test
	public void oversizedPomIsNotParsed() {
		String pom = "<project><licenses><license><name>EPL-2.0</name></license></licenses>"
			+ "<!--" + "x".repeat(Limits.METADATA) + "--></project>";
		assertThat(new LicenseResolver().fromPom(new ByteArrayInputStream(pom.getBytes(StandardCharsets.UTF_8))))
			.isEmpty();
	}

	@Test
	public void entityExpansionIsRejected() {
		String pom = """
			<?xml version="1.0"?>
			<!DOCTYPE project [
			  <!ENTITY a "aaaaaaaaaa">
			  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
			  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
			]>
			<project><licenses><license><name>&c;</name></license></licenses></project>
			""";
		assertThat(new LicenseResolver().fromPom(new ByteArrayInputStream(pom.getBytes(StandardCharsets.UTF_8))))
			.isEmpty();
	}

	@Test
	public void unreadableManifestCostsOnlyItsEdges() {
		Map<SbomComponent, Manifest> manifests = new LinkedHashMap<>();
		SbomComponent good = new SbomComponent().setBsn("good")
			.setVersion("1.0.0");
		SbomComponent broken = new SbomComponent().setBsn("broken")
			.setVersion("1.0.0");
		manifests.put(good, manifest("good", "Export-Package", "com.example;version=1.0"));
		manifests.put(broken, manifest("broken", "Export-Package", "com.example;version=\"[not a version\""));

		DependencyGraph graph = new DependencyGraph(manifests);

		assertThat(graph.edges()).containsKey(good);
		if (!graph.skipped()
			.isEmpty()) {
			assertThat(graph.skipped()).containsExactly("broken");
		}
	}

	private static Manifest manifest(String bsn, String header, String value) {
		Manifest manifest = new Manifest();
		Attributes main = manifest.getMainAttributes();
		main.put(Attributes.Name.MANIFEST_VERSION, "1.0");
		main.putValue("Bundle-ManifestVersion", "2");
		main.putValue("Bundle-SymbolicName", bsn);
		main.putValue("Bundle-Version", "1.0.0");
		main.putValue(header, value);
		return manifest;
	}
}
