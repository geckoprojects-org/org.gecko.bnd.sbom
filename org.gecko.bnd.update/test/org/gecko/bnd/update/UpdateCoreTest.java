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
package org.gecko.bnd.update;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.gecko.bnd.update.report.Reports;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.osgi.resource.Namespace;
import org.osgi.resource.Requirement;

import aQute.bnd.build.Workspace;
import aQute.bnd.osgi.resource.CapReqBuilder;
import aQute.bnd.osgi.resource.ResourceBuilder;
import aQute.bnd.version.MavenVersion;
import aQute.bnd.version.Version;

public class UpdateCoreTest {

	private static MavenVersion v(String version) {
		return new MavenVersion(version);
	}

	private static List<MavenVersion> versions(String... versions) {
		return Arrays.stream(versions)
			.map(MavenVersion::new)
			.toList();
	}

	@Test
	public void scopes() {
		assertThat(Scope.MICRO.allows(v("2.19.2"), v("2.19.3"))).isTrue();
		assertThat(Scope.MICRO.allows(v("2.19.2"), v("2.20.0"))).isFalse();
		assertThat(Scope.MINOR.allows(v("2.19.2"), v("2.20.0"))).isTrue();
		assertThat(Scope.MINOR.allows(v("2.19.2"), v("3.0.0"))).isFalse();
		assertThat(Scope.MAJOR.allows(v("2.19.2"), v("3.0.0"))).isTrue();
		assertThat(Scope.MAJOR.allows(v("2.19.2"), v("2.19.2"))).isFalse();
		assertThat(Scope.of(v("1.82"), v("1.85"))).isEqualTo(Scope.MINOR);
		assertThat(Scope.parse("Minor")).isEqualTo(Scope.MINOR);
		assertThatIllegalArgumentException().isThrownBy(() -> Scope.parse("patch"));
	}

	@Test
	public void policy() {
		VersionPolicy policy = VersionPolicy.parse(
			"default;scope=micro, com.fasterxml.jackson.core:*;scope=minor, org.bouncycastle:bcprov-jdk18on;scope=minor");

		assertThat(policy.scopeFor("com.fasterxml.jackson.core", "jackson-databind")).isEqualTo(Scope.MINOR);
		assertThat(policy.scopeFor("org.bouncycastle", "bcprov-jdk18on")).isEqualTo(Scope.MINOR);
		assertThat(policy.scopeFor("org.bouncycastle", "bcutil-jdk18on")).isEqualTo(Scope.MICRO);
		assertThat(policy.scopeFor("com.google.guava", "guava")).isEqualTo(Scope.MICRO);
		assertThat(VersionPolicy.parse(null)
			.defaultScope()).isEqualTo(Scope.MICRO);
		assertThat(VersionPolicy.parse("default;scope=minor")
			.scopeFor("x", "y")).isEqualTo(Scope.MINOR);
		assertThatIllegalArgumentException().isThrownBy(() -> VersionPolicy.parse("x:y"));
	}

	@Test
	public void fixedVersionsPerLine() {
		List<String> fixed = List.of("2.12.7.1", "2.13.4.2");

		assertThat(FixSelector.fixes(v("2.12.7"), fixed)).isFalse();
		assertThat(FixSelector.fixes(v("2.12.7.1"), fixed)).isTrue();
		assertThat(FixSelector.fixes(v("2.12.8"), fixed)).isTrue();
		assertThat(FixSelector.fixes(v("2.13.1"), fixed)).isFalse();
		assertThat(FixSelector.fixes(v("2.13.5"), fixed)).isTrue();
		assertThat(FixSelector.fixes(v("2.14.0"), fixed)).isTrue();
		assertThat(FixSelector.fixes(v("9.9.9"), List.of())).isFalse();
	}

	@Test
	public void selectSmallestFixWithinScope() {
		List<Vulnerability> vulnerabilities = List.of(new Vulnerability("CVE-1", "HIGH", List.of("2.19.3"), null),
			new Vulnerability("CVE-2", "MEDIUM", List.of("2.19.4", "2.20.1"), null));
		List<MavenVersion> available = versions("2.19.3", "2.19.4", "2.19.5", "2.20.0", "2.20.1");

		assertThat(FixSelector.select(v("2.19.2"), vulnerabilities, available, Scope.MICRO)).contains(v("2.19.4"));
		assertThat(FixSelector.select(v("2.19.2"), vulnerabilities, versions("2.19.3", "2.20.1"), Scope.MICRO))
			.isEmpty();
		assertThat(FixSelector.select(v("2.19.2"), vulnerabilities, versions("2.19.3", "2.20.1"), Scope.MINOR))
			.contains(v("2.20.1"));
	}

	static final String	TRIVY	= """
		{"Results":[{"Target":"sbom","Vulnerabilities":[
		 {"VulnerabilityID":"CVE-A","PkgName":"com.fasterxml.jackson.core:jackson-databind","InstalledVersion":"2.19.2","FixedVersion":"2.19.3","Severity":"HIGH","Title":"a"},
		 {"VulnerabilityID":"CVE-B","PkgName":"com.fasterxml.jackson.core:jackson-databind","InstalledVersion":"2.19.2","FixedVersion":"2.19.4, 2.20.1","Severity":"MEDIUM"},
		 {"VulnerabilityID":"CVE-C","PkgName":"org.bouncycastle:bcprov-jdk18on","InstalledVersion":"1.82","FixedVersion":"1.85","Severity":"CRITICAL"},
		 {"VulnerabilityID":"CVE-D","PkgName":"org.example:nofix","InstalledVersion":"1.0.0","FixedVersion":"","Severity":"LOW"},
		 {"VulnerabilityID":"CVE-E","PkgName":"not-maven","InstalledVersion":"1.0","FixedVersion":"1.1","Severity":"LOW"}
		]}]}
		""";

	static final String	SBOM	= """
		{"bomFormat":"CycloneDX","metadata":{"component":{"name":"minio.bndrun"}},"components":[
		 {"bom-ref":"pkg:maven/org.geckoprojects.libraries/io.minio@9.0.3","name":"io.minio","purl":"pkg:maven/org.geckoprojects.libraries/io.minio@9.0.3",
		  "properties":[{"name":"osgi:layer","value":"runbundle"}]},
		 {"bom-ref":"pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.19.2","name":"jackson-databind","purl":"pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.19.2",
		  "properties":[{"name":"osgi:layer","value":"runbundle"},{"name":"osgi:repository:name","value":"Central"}]},
		 {"bom-ref":"pkg:maven/org.bouncycastle/bcprov-jdk18on@1.82","name":"bcprov-jdk18on","purl":"pkg:maven/org.bouncycastle/bcprov-jdk18on@1.82",
		  "properties":[{"name":"osgi:embedded:in","value":"pkg:maven/org.geckoprojects.libraries/io.minio@9.0.3"},{"name":"osgi:embedded:source","value":"packages org.bouncycastle from -buildpath"}]}
		]}
		""";

	private static ByteArrayInputStream in(String text) {
		return new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8));
	}

	private static final VersionSource REPOSITORY = (g, a) -> switch (g + ":" + a) {
		case "com.fasterxml.jackson.core:jackson-databind" -> versions("2.19.3", "2.19.4", "2.20.1", "2.21.0-rc1");
		case "org.bouncycastle:bcprov-jdk18on" -> versions("1.83", "1.85");
		default -> List.of();
	};

	@Test
	public void trivyAndSbomAreRead() throws Exception {
		TrivyReport trivy = TrivyReport.read(in(TRIVY));
		Sbom sbom = Sbom.read(in(SBOM));

		assertThat(trivy.vulnerabilities()).hasSize(3);
		assertThat(trivy.vulnerabilities()
			.get(new Library("com.fasterxml.jackson.core", "jackson-databind", "2.19.2"))).hasSize(2);
		assertThat(sbom.application()).isEqualTo("minio.bndrun");
		assertThat(sbom.locations("org.bouncycastle", "bcprov-jdk18on")).singleElement()
			.satisfies(l -> {
				assertThat(l.isEmbedded()).isTrue();
				assertThat(l.bundle()).isEqualTo("io.minio");
			});
	}

	@Test
	public void vulnerabilityCheckAgainstTheRepositories() throws Exception {
		CheckReport report = new VulnerabilityCheck(REPOSITORY, VersionPolicy.defaults())
			.check(Sbom.read(in(SBOM)), TrivyReport.read(in(TRIVY)));
		Map<String, Proposal> byGa = new HashMap<>();
		report.proposals()
			.forEach(p -> byGa.put(p.library()
				.ga(), p));

		assertThat(byGa.get("com.fasterxml.jackson.core:jackson-databind")).satisfies(p -> {
			assertThat(p.status()).isEqualTo(Proposal.Status.UPDATE);
			assertThat(p.proposed()).isEqualTo(v("2.19.4"));
		});
		assertThat(byGa.get("org.bouncycastle:bcprov-jdk18on")).satisfies(p -> {
			assertThat(p.status()).isEqualTo(Proposal.Status.OUTSIDE_POLICY);
			assertThat(p.needed()).isEqualTo(Scope.MINOR);
			assertThat(p.locations()).singleElement()
				.satisfies(l -> assertThat(l.isEmbedded()).isTrue());
		});
		assertThat(byGa.get("org.example:nofix")
			.status()).isEqualTo(Proposal.Status.NO_FIX);

		String markdown = Reports.markdown(report);
		assertThat(markdown).contains("**2.19.4** (micro)")
			.contains("needs a minor update (allowed: micro)")
			.contains("embedded in `io.minio`");
		assertThat(Reports.json(report)).contains("\"status\":\"OUTSIDE_POLICY\"");
	}

	@Test
	public void vulnerabilityCheckAgainstFoundUpdates() throws Exception {
		Update jackson = new Update(new Library("com.fasterxml.jackson.core", "jackson-databind", "2.19.2"), "Central",
			null, versions("2.19.3"), Scope.MICRO, v("2.19.3"), v("2.19.3"));

		CheckReport report = VulnerabilityCheck.againstUpdates(List.of(jackson), VersionPolicy.defaults())
			.check(null, TrivyReport.read(in(TRIVY)));

		// 2.19.3 fixes CVE-A but not CVE-B: the found update is not enough
		assertThat(report.proposals()
			.get(0)
			.status()).isEqualTo(Proposal.Status.NO_FIX);
	}

	@Test
	public void updatesReport() throws Exception {
		Update proposed = new Update(new Library("g", "a", "1.0.0"), "Central", "cnf/central.mvn",
			versions("1.0.1", "1.1.0"), Scope.MICRO, v("1.0.1"), v("1.1.0"));
		Update outside = new Update(new Library("g", "b", "1.0.0"), "Central", "cnf/central.mvn", versions("2.0.0"),
			Scope.MICRO, null, v("2.0.0"));

		assertThat(Reports.markdown(List.of(proposed, outside))).contains("| `g:a` | 1.0.0 | **1.0.1** | micro | 1.1.0 (minor) | Central |")
			.contains("`g:b:1.0.0` → 2.0.0 needs a major update (allowed: micro)");
		assertThat(Reports.json(List.of(proposed))).contains("\"proposed\":\"1.0.1\"");
	}

	@Test
	public void flavorIsKept() {
		assertThat(Scope.MINOR.allows(v("33.5.0-jre"), v("33.7.2-jre"))).isTrue();
		assertThat(Scope.MINOR.allows(v("33.5.0-jre"), v("33.7.2-android"))).isFalse();
		assertThat(Scope.MICRO.allows(v("2.19.2"), v("2.19.3"))).isTrue();
		assertThat(Scope.MICRO.allows(v("1.1.10.8"), v("1.1.10.9"))).isTrue();
		assertThat(FixSelector.select(v("33.5.0-jre"),
			List.of(new Vulnerability("CVE-G", "HIGH", List.of("33.7.2"), null)),
			versions("33.7.2-android", "33.7.2-jre"), Scope.MINOR)).contains(v("33.7.2-jre"));
	}

	@Test
	public void runbundlesAreComparedWithoutQuotes() {
		assertThat(ResolveCheck.clauses("org.apache.felix.scr;version='[2.2.6,2.2.7)',"
			+ "io.minio;version=snapshot," + "slf4j.api;version=\"[2.0.17, 2.0.18)\""))
				.containsExactly("org.apache.felix.scr;version=[2.2.6,2.2.7)", "io.minio;version=snapshot",
					"slf4j.api;version=[2.0.17,2.0.18)");
		assertThat(ResolveCheck.clauses(null)).isEmpty();
	}

	@Test
	public void resolveReport() throws Exception {
		BndrunResult unchanged = new BndrunResult("a/x.bndrun", BndrunResult.Status.UNCHANGED, List.of("a;version=1"),
			List.of("a;version=1"), List.of(), List.of(), List.of(), null);
		BndrunResult changed = new BndrunResult("a/y.bndrun", BndrunResult.Status.CHANGED,
			List.of("g;version=[33.5.0,33.5.1)"), List.of("g;version=[33.6.0,33.6.1)"),
			List.of("g;version=[33.6.0,33.6.1)"), List.of("g;version=[33.5.0,33.5.1)"), List.of(), null);
		BndrunResult failed = new BndrunResult("a/z.bndrun", BndrunResult.Status.FAILED, List.of(), List.of(), List.of(),
			List.of(), List.of("aQute.libg 7.4.0 -> osgi.wiring.package: org.slf4j; version=[2.0.0,3.0.0)"), "failed");
		ResolveReport report = new ResolveReport(List.of(unchanged, changed, failed));

		assertThat(report.allResolve()).isFalse();
		assertThat(new ResolveReport(List.of(unchanged, changed)).allResolve()).isTrue();
		assertThat(Reports.markdown(report)).contains("**Not every bndrun resolves.**")
			.contains("- removed `g;version=[33.5.0,33.5.1)`")
			.contains("- added `g;version=[33.6.0,33.6.1)`")
			.contains("- `aQute.libg 7.4.0 -> osgi.wiring.package: org.slf4j; version=[2.0.0,3.0.0)`");
		assertThat(Reports.json(report)).contains("\"allResolve\":false");
	}

	@Test
	public void variantWithDigitsIsKept() {
		// byte-buddy publishes 1.18.17 and 1.18.17-jdk5: an installed version without a suffix
		// stays without one
		assertThat(Scope.MAJOR.allows(v("1.18.4"), v("1.18.17-jdk5"))).isFalse();
		assertThat(Scope.MAJOR.allows(v("1.18.4"), v("1.18.17"))).isTrue();
		assertThat(Scope.MAJOR.allows(v("1.18.4-jdk5"), v("1.18.17-jdk5"))).isTrue();
		// a pre-release is not a variant: it moves on to the release
		assertThat(Scope.MINOR.allows(v("2.0.0-rc1"), v("2.0.0"))).isTrue();
		assertThat(Scope.MINOR.allows(v("2.0.0-beta"), v("2.1.0"))).isTrue();
	}

	@Test
	public void dateVersionIsNoUpdate() {
		// commons-collections 20040616 compares higher than 3.2.2, but is an ancient release
		assertThat(Scope.MAJOR.allows(v("3.2.2"), v("20040616"))).isFalse();
		assertThat(Scope.successor(v("3.2.2"), v("20040616"))).isFalse();
		assertThat(Scope.MAJOR.allows(v("20030203.000550"), v("20040616"))).isTrue();
		// calendar versions with a year as major are a regular scheme
		assertThat(Scope.MAJOR.allows(v("2023.1.0"), v("2024.2.0"))).isTrue();
	}

	@Test
	public void indexOrigin(@TempDir Path ws) {
		File workspace = ws.toFile();
		File cache = new File(workspace, "cnf/cache");

		assertThat(IndexOrigin.of(new File(workspace, "cnf/central.mvn"), workspace, cache))
			.isEqualTo(IndexOrigin.WORKSPACE);

		IndexOrigin library = IndexOrigin.of(new File(cache,
			"7.4.0/expanded/urn%resource%org.eclipse.fennec.emf.osgi.bnd.library.workspace-1.1.0/template/fennecEMF.maven"),
			workspace, cache);
		assertThat(library.kind()).isEqualTo(IndexOrigin.Kind.LIBRARY);
		assertThat(library.source()).isEqualTo("org.eclipse.fennec.emf.osgi.bnd.library.workspace 1.1.0");
		assertThat(library.isWritable()).isFalse();
		assertThat(library).hasToString("library org.eclipse.fennec.emf.osgi.bnd.library.workspace 1.1.0");

		IndexOrigin external = IndexOrigin.of(new File(workspace.getParentFile(), "other/central.mvn"), workspace,
			cache);
		assertThat(external.kind()).isEqualTo(IndexOrigin.Kind.EXTERNAL);
		assertThat(external.isWritable()).isFalse();

		assertThat(IndexOrigin.of(new File("/anywhere/x.mvn"), null, null)).isEqualTo(IndexOrigin.WORKSPACE);
	}

	@Test
	public void libraryIndexIsNotWritten(@TempDir Path ws) throws Exception {
		Files.createDirectories(ws.resolve("cnf"));
		Files.writeString(ws.resolve("cnf/build.bnd"), "");
		String relative = "cnf/cache/7.4.0/expanded/urn%resource%org.example.lib-1.1.0/template/lib.maven";
		Path index = ws.resolve(relative);
		Files.createDirectories(index.getParent());
		String content = "org.apache.felix:org.apache.felix.scr:2.2.6\n";
		Files.writeString(index, content);

		Library scr = new Library("org.apache.felix", "org.apache.felix.scr", "2.2.6");
		// as the finder reports it ...
		Update reported = new Update(scr, "Library", relative,
			IndexOrigin.of(index.toFile(), ws.toFile(), ws.resolve("cnf/cache")
				.toFile()),
			versions("2.3.0"), Scope.MAJOR, v("2.3.0"), v("2.3.0"));
		// ... and as a caller that does not know: the applier checks the file itself
		Update unknown = new Update(scr, "Library", relative, versions("2.3.0"), Scope.MAJOR, v("2.3.0"), v("2.3.0"));

		ApplyReport report = new UpdateApplier(ws.toFile(), null).apply(List.of(reported, unknown),
			UpdateApplier.Mode.EACH);

		assertThat(report.updates()).hasSize(2)
			.allSatisfy(a -> {
				assertThat(a.status()).isEqualTo(AppliedUpdate.Status.READ_ONLY_INDEX);
				assertThat(a.reason()).contains("bnd library org.example.lib 1.1.0")
					.contains("update the library");
			});
		assertThat(Files.readString(index)).isEqualTo(content);
		assertThat(Reports.json(report)).contains("\"kind\":\"library\"")
			.contains("\"source\":\"org.example.lib 1.1.0\"")
			.contains("\"writable\":false");
		assertThat(Reports.markdown(List.of(reported))).contains("(library org.example.lib 1.1.0, read-only)");
	}

	@Test
	public void optionalRequirementsDoNotFailResolution() {
		Requirement optional = new CapReqBuilder("osgi.wiring.package")
			.addDirective(Namespace.REQUIREMENT_RESOLUTION_DIRECTIVE, Namespace.RESOLUTION_OPTIONAL)
			.addDirective(Namespace.REQUIREMENT_FILTER_DIRECTIVE, "(osgi.wiring.package=org.antlr.v4.gui)")
			.buildSyntheticRequirement();
		Requirement mandatory = new CapReqBuilder("osgi.wiring.package")
			.addDirective(Namespace.REQUIREMENT_FILTER_DIRECTIVE, "(osgi.wiring.package=org.osgi.framework)")
			.buildSyntheticRequirement();

		assertThat(ResolveCheck.mandatory(List.of(optional, mandatory))).containsExactly(mandatory);
		assertThat(ResolveCheck.mandatory(List.of(optional))).containsExactly(optional);
	}

	@Test
	public void consequencesAreFilteredOut() throws Exception {
		Requirement supplementEe = requirementOf("junit-platform-commons__8", "1.14.2",
			new CapReqBuilder("osgi.ee").addDirective(Namespace.REQUIREMENT_FILTER_DIRECTIVE,
				"(&(osgi.ee=JavaSE)(version>=1.8.0)(!(version>=9.0.0)))"));
		Requirement ownEe = requirementOf("org.example.lib", "1.0.0", new CapReqBuilder("osgi.ee")
			.addDirective(Namespace.REQUIREMENT_FILTER_DIRECTIVE, "(&(osgi.ee=JavaSE)(version>=25))"));
		Requirement root = new CapReqBuilder("osgi.identity")
			.addDirective(Namespace.REQUIREMENT_FILTER_DIRECTIVE, "(osgi.identity=org.eclipse.fennec.m2x.ocl.ide)")
			.buildSyntheticRequirement();
		Requirement framework = requirementOf("org.eclipse.emf.ecore", "2.41.0",
			new CapReqBuilder("osgi.wiring.package").addDirective(Namespace.REQUIREMENT_FILTER_DIRECTIVE,
				"(&(osgi.wiring.package=org.osgi.framework)(version>=1.5.0)(!(version>=2.0.0)))"));

		assertThat(ResolveCheck.relevant(List.of(root, supplementEe, framework))).containsExactly(framework);
		// an osgi.ee requirement of a regular bundle is a real cause
		assertThat(ResolveCheck.relevant(List.of(root, ownEe))).containsExactly(ownEe);
		// never emptied: a -runrequires entry alone is the cause (the bundle does not exist)
		assertThat(ResolveCheck.relevant(List.of(root))).containsExactly(root);
		assertThat(ResolveCheck.relevant(List.of(supplementEe))).containsExactly(supplementEe);
	}

	private static Requirement requirementOf(String bsn, String version, CapReqBuilder requirement)
		throws Exception {
		ResourceBuilder resource = new ResourceBuilder();
		resource.addCapability(new CapReqBuilder("osgi.identity").addAttribute("osgi.identity", bsn)
			.addAttribute("version", new Version(version))
			.addAttribute("type", "osgi.bundle"));
		resource.addRequirement(requirement);
		return resource.build()
			.getRequirements(requirement.getNamespace())
			.get(0);
	}

	@Test
	public void missingFrameworkIsTheReason() throws Exception {
		BndrunResult failed = new BndrunResult("ocl/ocl.feature.bndrun", BndrunResult.Status.FAILED, List.of(),
			List.of(), List.of(), List.of(),
			List.of("org.eclipse.emf.ecore 2.41.0 -> osgi.wiring.package: org.osgi.framework; version=[1.5.0,2.0.0)"),
			"failed", List.of("-runfw: org.apache.felix.framework;version=[7.0.5,7.0.5]"));

		assertThat(UpdateApplier.failure(failed)).startsWith(
			"ocl/ocl.feature.bndrun does not resolve: -runfw: org.apache.felix.framework;version=[7.0.5,7.0.5] pins a version the update removes")
			.contains("(therefore unresolved: org.eclipse.emf.ecore 2.41.0");
		assertThat(Reports.markdown(new ResolveReport(List.of(failed))))
			.contains("- **`-runfw: org.apache.felix.framework;version=[7.0.5,7.0.5]` matches nothing in the repositories**");
		assertThat(Reports.json(new ResolveReport(List.of(failed)))).contains("\"missing\":[")
			.contains("\"-runfw: org.apache.felix.framework;version=[7.0.5,7.0.5]\"");

		BndrunResult plain = new BndrunResult("a/z.bndrun", BndrunResult.Status.FAILED, List.of(), List.of(),
			List.of(), List.of(), List.of("x 1.0.0 -> osgi.wiring.package: y"), "failed");
		assertThat(UpdateApplier.failure(plain)).isEqualTo("a/z.bndrun does not resolve: x 1.0.0 -> osgi.wiring.package: y");
	}

	@Test
	public void revertedUpdatesThatFailOnEachOther() {
		Update asm = update("org.ow2.asm", "asm", "9.9.1", "9.10");
		Update tree = update("org.ow2.asm", "asm-tree", "9.9.1", "9.10");
		Update spifly = update("org.apache.aries.spifly", "org.apache.aries.spifly.dynamic.bundle", "1.3.7", "1.3.8");
		Update scr = update("org.apache.felix", "org.apache.felix.scr", "2.2.6", "2.3.0");
		Update other = update("org.example", "other", "1.0.0", "2.0.0");

		Map<Update, List<String>> unresolved = new HashMap<>();
		// asm 9.10 alone: asm-tree 9.9.1 still pins asm to [9.9.1,9.10.0)
		unresolved.put(asm, List.of(
			"org.objectweb.asm.tree 9.9.1 -> osgi.wiring.package: org.objectweb.asm; version=[9.9.1,9.10.0)"));
		// asm-tree 9.10 alone needs asm 9.10
		unresolved.put(tree, List.of(
			"org.objectweb.asm.tree 9.10.0 -> osgi.wiring.package: org.objectweb.asm; version=[9.10.0,9.11.0)"));
		// spifly 1.3.8 needs asm >= 9.10
		unresolved.put(spifly, List.of(
			"org.apache.aries.spifly.dynamic.bundle 1.3.8 -> osgi.wiring.package: org.objectweb.asm.commons; version=[9.10.0,10.0.0)"));
		// unrelated: needs something no reverted update provides
		unresolved.put(other, List.of("org.example.other 2.0.0 -> osgi.wiring.package: org.example.missing"));
		// scr: reverted without unresolved requirements (e.g. the build failed) - not grouped

		Map<Update, RevertedGroups.Installed> installed = new HashMap<>();
		installed.put(asm, new RevertedGroups.Installed("org.objectweb.asm 9.9.1",
			Set.of("osgi.wiring.package:org.objectweb.asm", "osgi.wiring.package:org.objectweb.asm.signature")));
		installed.put(tree, new RevertedGroups.Installed("org.objectweb.asm.tree 9.9.1",
			Set.of("osgi.wiring.package:org.objectweb.asm.tree")));
		installed.put(spifly, new RevertedGroups.Installed("org.apache.aries.spifly.dynamic.bundle 1.3.7",
			Set.of("osgi.wiring.package:org.apache.aries.spifly")));
		installed.put(other, new RevertedGroups.Installed("org.example.other 1.0.0", Set.of()));

		List<Update> reverted = List.of(asm, scr, tree, other, spifly);
		// spifly needs org.objectweb.asm.commons, which none of the reverted updates provides:
		// it stays alone ...
		assertThat(RevertedGroups.of(reverted, unresolved, installed)).singleElement()
			.satisfies(g -> assertThat(g.only()).isEqualTo("org.ow2.asm:asm,org.ow2.asm:asm-tree"));

		// ... until asm-commons is among the reverted updates
		Update commons = update("org.ow2.asm", "asm-commons", "9.9.1", "9.10");
		unresolved.put(commons, List.of(
			"org.objectweb.asm.commons 9.10.0 -> osgi.wiring.package: org.objectweb.asm.tree; version=[9.10.0,9.11.0)"));
		installed.put(commons, new RevertedGroups.Installed("org.objectweb.asm.commons 9.9.1",
			Set.of("osgi.wiring.package:org.objectweb.asm.commons")));
		List<RevertedGroup> groups = RevertedGroups.of(List.of(asm, scr, tree, other, spifly, commons), unresolved,
			installed);
		assertThat(groups).singleElement()
			.satisfies(g -> assertThat(g.only())
				.isEqualTo("org.ow2.asm:asm,org.ow2.asm:asm-tree,org.apache.aries.spifly:org.apache.aries.spifly.dynamic.bundle,org.ow2.asm:asm-commons"));

		ApplyReport report = new ApplyReport(UpdateApplier.Mode.EACH,
			List.of(new AppliedUpdate(asm, AppliedUpdate.Status.REVERTED, "x")), new ResolveReport(List.of()), null,
			new ResolveReport(List.of()), groups);
		assertThat(Reports.markdown(report)).contains("### Reverted updates that fail on each other")
			.contains("`apply --mode all --only org.ow2.asm:asm,org.ow2.asm:asm-tree,");
	}

	@Test
	public void blameIsParsed() {
		RevertedGroups.Blame blame = RevertedGroups.Blame
			.parse("org.eclipse.emf.ecore 2.41.0 -> osgi.wiring.package: org.osgi.framework; version=[1.5.0,2.0.0)");
		assertThat(blame).isEqualTo(
			new RevertedGroups.Blame("org.eclipse.emf.ecore 2.41.0", "osgi.wiring.package", "org.osgi.framework"));
		assertThat(RevertedGroups.Blame.parse("-runrequires -> osgi.identity: x")
			.who()).isEqualTo("-runrequires");
		assertThat(RevertedGroups.Blame.parse("garbage")).isNull();
	}

	@Test
	public void runfwWithoutContainerIsMissing() {
		// bnd returns no container for an entry it cannot find
		List<String> missing = new ArrayList<>();
		ResolveCheck.missing("-runfw", "org.apache.felix.framework;version='[7.0.5,7.0.5]'", List.of(), missing);
		ResolveCheck.missing("-runpath", "lib/x.jar;version=file", List.of(), missing);
		ResolveCheck.missing("-runpath", null, List.of(), missing);
		assertThat(missing).containsExactly("-runfw: org.apache.felix.framework;version=[7.0.5,7.0.5]");
	}

	@Test
	public void buildtimeScope() {
		VersionPolicy policy = VersionPolicy
			.parse("default;scope=micro, buildtime;scope=minor, org.junit.jupiter:*;scope=major");
		assertThat(policy.scopeFor("org.jacoco", "org.jacoco.core", Update.Usage.BUILD_TIME)).isEqualTo(Scope.MINOR);
		assertThat(policy.scopeFor("org.jacoco", "org.jacoco.core", Update.Usage.RUNTIME)).isEqualTo(Scope.MICRO);
		assertThat(policy.scopeFor("org.jacoco", "org.jacoco.core", Update.Usage.UNKNOWN)).isEqualTo(Scope.MICRO);
		// a per-library entry comes first
		assertThat(policy.scopeFor("org.junit.jupiter", "junit-jupiter-api", Update.Usage.BUILD_TIME))
			.isEqualTo(Scope.MAJOR);
		// --scope overrides the default, not the build-time scope
		assertThat(policy.withDefault(Scope.MAJOR)
			.buildtimeScope()).isEqualTo(Scope.MINOR);
		assertThat(VersionPolicy.defaults()
			.scopeFor("g", "a", Update.Usage.BUILD_TIME)).isEqualTo(Scope.MICRO);
	}

	@Test
	public void shadowedByAnotherIndex() {
		Library scrLibrary = new Library("org.apache.felix", "org.apache.felix.scr", "2.2.6");
		Library scrCentral = new Library("org.apache.felix", "org.apache.felix.scr", "2.3.0");
		Library emfCentral = new Library("org.eclipse.emf", "org.eclipse.emf.common", "2.29.0");
		Library emfCentral2 = new Library("org.eclipse.emf", "org.eclipse.emf.common", "2.44.0");
		Library emfLibrary = new Library("org.eclipse.emf", "org.eclipse.emf.common", "2.44.0");
		Library jre = new Library("com.google.guava", "guava", "33.5.0-jre");
		Library android = new Library("com.google.guava", "guava", "33.6.0-android");

		Map<String, String> shadows = UpdateFinder.shadows(List.of(new UpdateFinder.Indexed(scrLibrary, "EMF"),
			new UpdateFinder.Indexed(scrCentral, "Central"), new UpdateFinder.Indexed(emfCentral, "Central"),
			new UpdateFinder.Indexed(emfCentral2, "Central"), new UpdateFinder.Indexed(emfLibrary, "EMF"),
			new UpdateFinder.Indexed(jre, "Central"), new UpdateFinder.Indexed(android, "Other")));

		assertThat(shadows).containsEntry(scrLibrary + "@EMF", "2.3.0 in Central")
			// shadowed by another index, not by a second line of its own index
			.containsEntry(emfCentral + "@Central", "2.44.0 in EMF")
			.doesNotContainKey(scrCentral + "@Central")
			.doesNotContainKey(emfCentral2 + "@Central")
			.doesNotContainKey(emfLibrary + "@EMF")
			// another variant does not shadow
			.doesNotContainKey(jre + "@Central");
	}

	@Test
	public void shadowedUpdatesReport(@TempDir Path ws) throws Exception {
		Update shadowed = new Update(new Library("org.apache.felix", "org.apache.felix.scr", "2.2.6"), "EMF",
			"cnf/cache/7.4.0/expanded/urn%resource%org.example.lib-1.1.0/template/x.maven",
			new IndexOrigin(IndexOrigin.Kind.LIBRARY, "org.example.lib 1.1.0"), versions("2.2.18", "2.3.0"),
			Scope.MICRO, null, v("2.3.0"), Update.Usage.RUNTIME, "2.3.0 in Central");
		Update runtime = new Update(new Library("g", "rt", "1.0.0"), "Central", "cnf/central.mvn", IndexOrigin.WORKSPACE,
			versions("1.0.1", "1.1.0"), Scope.MICRO, v("1.0.1"), v("1.1.0"), Update.Usage.RUNTIME, null);
		Update outsideRuntime = new Update(new Library("g", "rt2", "1.0.0"), "Central", "cnf/central.mvn",
			IndexOrigin.WORKSPACE, versions("2.0.0"), Scope.MICRO, null, v("2.0.0"), Update.Usage.RUNTIME, null);
		Update junit = new Update(new Library("org.junit.jupiter", "junit-jupiter-api", "5.14.2"), "Central",
			"cnf/central.mvn", IndexOrigin.WORKSPACE, versions("5.14.4", "6.1.3"), Scope.MICRO, v("5.14.4"), v("6.1.3"),
			Update.Usage.BUILD_TIME, null);
		Update bnd = new Update(new Toolchain("7.4.0", "gradle.properties bnd_version").library(),
			"bnd toolchain", "gradle.properties", new IndexOrigin(IndexOrigin.Kind.TOOLCHAIN, "gradle.properties bnd_version"),
			versions("7.5.0"), Scope.MICRO, null, v("7.5.0"), Update.Usage.BUILD_TIME, null);
		List<Update> updates = List.of(shadowed, runtime, outsideRuntime, junit, bnd);

		String md = Reports.markdown(updates);
		assertThat(md).contains("| Library | Installed | Proposed | Allowed | Latest | Use | Repository |")
			.contains("| `g:rt` | 1.0.0 | **1.0.1** | micro | 1.1.0 (minor) | runtime | Central |")
			.contains("| `org.junit.jupiter:junit-jupiter-api` | 5.14.2 | **5.14.4** | micro | 6.1.3 (major) | build time | Central |")
			.contains("### Build time: newer versions beyond the policy")
			.contains("- `org.junit.jupiter:junit-jupiter-api:5.14.2` → 6.1.3 (major, build time only)")
			.contains("- `biz.aQute.bnd:biz.aQute.bndlib:7.4.0` (toolchain gradle.properties bnd_version, read-only) → 7.5.0 (minor, build time only)")
			.contains("### Outside the version policy")
			.contains("- `g:rt2:1.0.0` → 2.0.0 needs a major update")
			.contains("### Shadowed by another index")
			.contains("- `org.apache.felix:org.apache.felix.scr:2.2.6` in EMF (library org.example.lib 1.1.0, read-only) - the workspace uses 2.3.0 in Central");
		// a shadowed or build-time entry is not "outside the version policy"
		assertThat(md.substring(md.indexOf("### Outside the version policy"), md.indexOf("### Shadowed")))
			.doesNotContain("scr")
			.doesNotContain("bndlib");
		assertThat(md.substring(0, md.indexOf("### Build time"))).doesNotContain("org.apache.felix.scr");
		assertThat(Reports.json(updates)).contains("\"usage\":\"build_time\"")
			.contains("\"shadowedBy\":\"2.3.0 in Central\"");

		// apply: a shadowed entry and the toolchain are not written
		Files.createDirectories(ws.resolve("cnf"));
		Files.writeString(ws.resolve("cnf/build.bnd"), "");
		Files.writeString(ws.resolve("gradle.properties"), "bnd_version=7.4.0\n");
		Update bndProposed = new Update(bnd.library(), bnd.repository(), bnd.index(), bnd.origin(), bnd.available(),
			Scope.MINOR, v("7.5.0"), v("7.5.0"), Update.Usage.BUILD_TIME, null);
		ApplyReport report = new UpdateApplier(ws.toFile(), null).apply(List.of(shadowed, bndProposed),
			UpdateApplier.Mode.EACH);
		assertThat(report.updates()
			.get(0)
			.status()).isEqualTo(AppliedUpdate.Status.NOT_PROPOSED);
		assertThat(report.updates()
			.get(0)
			.reason()).contains("not used: 2.3.0 in Central is higher");
		assertThat(report.updates()
			.get(1)
			.status()).isEqualTo(AppliedUpdate.Status.READ_ONLY_INDEX);
		assertThat(report.updates()
			.get(1)
			.reason()).contains("set in gradle.properties bnd_version");
		assertThat(Files.readString(ws.resolve("gradle.properties"))).isEqualTo("bnd_version=7.4.0\n");
		assertThat(Reports.markdown(report)).doesNotContain("org.apache.felix.scr:2.2.6` → null needs");
	}

	@Test
	public void applicationBndruns(@TempDir Path ws) throws Exception {
		Files.createDirectories(ws.resolve("cnf"));
		Files.writeString(ws.resolve("cnf/build.bnd"), "");
		Path app = Files.createDirectories(ws.resolve("app"));
		Files.writeString(app.resolve("bnd.bnd"), "");
		Files.writeString(app.resolve("app.bndrun"), "-sbom: level=medium\n"
			+ "-runfw: org.apache.felix.framework\n"
			+ "-runbundles: org.apache.felix.scr;version='[2.3.0,2.3.1)',org.example.app;version=snapshot\n");
		Files.writeString(app.resolve("test.bndrun"), "-runfw: org.apache.felix.framework\n"
			+ "-runbundles: junit-jupiter-api;version='[5.14.2,5.14.3)',org.osgi.test.junit5;version='[1.3.0,1.3.1)'\n");
		Files.writeString(app.resolve("other.bndrun"), "-runbundles: org.example.tool;version='[1.0.0,1.0.1)'\n");

		try (Workspace workspace = new Workspace(ws.toFile())) {
			RuntimeArtifacts runtime = RuntimeArtifacts.of(workspace);
			// with an -sbom bndrun, only those are the application
			assertThat(runtime.bndruns()).containsExactly("app/app.bndrun");
			assertThat(runtime.contains("org.apache.felix.scr", new Version("2.3.0"))).isTrue();
			assertThat(runtime.contains("org.apache.felix.scr", new Version("2.2.6"))).isFalse();
			assertThat(runtime.contains("org.apache.felix.framework", new Version("7.0.5"))).isTrue();
			assertThat(runtime.contains("junit-jupiter-api", new Version("5.14.2"))).isFalse();
			assertThat(runtime.contains("org.example.tool", new Version("1.0.0"))).isFalse();
		}

		// without any -sbom bndrun: every bndrun that is not a test run
		Files.writeString(app.resolve("app.bndrun"), "-runbundles: org.apache.felix.scr;version='[2.3.0,2.3.1)'\n");
		try (Workspace workspace = new Workspace(ws.toFile())) {
			assertThat(RuntimeArtifacts.of(workspace)
				.bndruns()).containsExactlyInAnyOrder("app/app.bndrun", "app/other.bndrun");
		}
	}

	@Test
	public void testRunsAreRecognized() {
		for (String bsn : List.of("junit-jupiter-api", "junit-platform-commons", "org.junit.jupiter.api", "junit",
			"org.opentest4j", "biz.aQute.tester.junit-platform", "org.osgi.test.junit5", "org.osgi.test.common",
			"org.osgi.test.junit5.cm", "assertj-core", "org.mockito.mockito-core", "org.hamcrest")) {
			assertThat(RuntimeArtifacts.isTestRun(RuntimeArtifacts.clauses(bsn + ";version='[1,2)'"))).as(bsn)
				.isTrue();
		}
		assertThat(RuntimeArtifacts.isTestRun(RuntimeArtifacts
			.clauses("org.apache.felix.scr;version='[2.3.0,2.3.1)',junitlike.bundle;version=1"))).isFalse();
	}

	@Test
	public void toolchainIsDetected(@TempDir Path ws) throws Exception {
		assertThat(Toolchain.detect(ws.toFile())).isNull();

		Files.writeString(ws.resolve("settings.gradle"),
			"pluginManagement {\n  plugins {\n    id 'biz.aQute.bnd.workspace' version '7.3.0'\n  }\n}\n");
		assertThat(Toolchain.detect(ws.toFile())).isEqualTo(new Toolchain("7.3.0", "settings.gradle"));

		// gradle.properties wins; a property reference is not a version
		Files.writeString(ws.resolve("gradle.properties"), "bnd_version=7.4.0\nother=x\n");
		assertThat(Toolchain.detect(ws.toFile())).isEqualTo(new Toolchain("7.4.0", "gradle.properties bnd_version"));
		Files.writeString(ws.resolve("gradle.properties"), "bnd_version=${other}\n");
		assertThat(Toolchain.detect(ws.toFile())).isEqualTo(new Toolchain("7.3.0", "settings.gradle"));

		Path maven = Files.createDirectories(ws.resolve("maven"));
		Files.writeString(maven.resolve("pom.xml"),
			"<project><properties><bnd.version>7.4.0</bnd.version></properties></project>");
		assertThat(Toolchain.detect(maven.toFile())).isEqualTo(new Toolchain("7.4.0", "pom.xml bnd.version"));
		assertThat(Toolchain.detect(maven.toFile())
			.library()).isEqualTo(new Library("biz.aQute.bnd", "biz.aQute.bndlib", "7.4.0"));
	}

	private static Update update(String g, String a, String from, String to) {
		return new Update(new Library(g, a, from), "Central", "cnf/central.mvn", versions(to), Scope.MAJOR, v(to),
			v(to));
	}
}
