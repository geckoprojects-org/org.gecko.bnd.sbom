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

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import aQute.bnd.build.Workspace;
import aQute.bnd.header.Attrs;
import aQute.bnd.header.Parameters;
import aQute.bnd.osgi.Constants;
import aQute.bnd.osgi.Processor;
import aQute.bnd.version.Version;
import aQute.bnd.version.VersionRange;
import biz.aQute.resolve.Bndrun;

/**
 * What the application consists of: the {@code -runbundles}, {@code -runfw} and {@code -runpath}
 * of the workspace's application bndruns, as written in the files — read, not resolved.
 * Everything else in the indexes is only needed to build or test.
 * <p>
 * The application bndruns are the ones with an {@code -sbom} instruction — they describe what is
 * shipped. Without any, every bndrun that is not a test run counts: a test run has a test bundle
 * in its {@code -runbundles} — JUnit, OpenTest4J, the bnd tester, OSGi-Test, AssertJ, Mockito or
 * Hamcrest.
 */
final class RuntimeArtifacts {

	/** one entry of a run instruction; {@code range == null} accepts every version */
	record Clause(String bsn, VersionRange range) {

		boolean accepts(String bsn, Version version) {
			return this.bsn.equals(bsn) && (range == null || range.includes(version));
		}
	}

	/** The instruction that marks an application bndrun. */
	static final String					SBOM			= "-sbom";

	/** Bundles that make a bndrun a test run (prefixes of the bsn). */
	private static final List<String>	TEST_BUNDLES	= List.of(
		// JUnit 4/5 and its runtime, the bnd tester
		"junit", "org.junit", "org.opentest4j", "biz.aQute.tester",
		// OSGi-Test (org.osgi.test.junit5, .common, .junit5.cm, .assertj.*)
		"org.osgi.test",
		// assertion and mocking libraries
		"assertj-core", "org.assertj", "org.mockito", "org.hamcrest");

	private static final List<String>	INSTRUCTIONS	= List.of(Constants.RUNBUNDLES, Constants.RUNFW,
		Constants.RUNPATH);

	private final List<Clause>			clauses;
	private final List<String>			bndruns;

	RuntimeArtifacts(List<Clause> clauses, List<String> bndruns) {
		this.clauses = List.copyOf(clauses);
		this.bndruns = List.copyOf(bndruns);
	}

	/** The application bndruns the clauses come from, relative to the workspace. */
	List<String> bndruns() {
		return bndruns;
	}

	/** {@code true} if the bundle is part of an application bndrun. */
	boolean contains(String bsn, Version version) {
		return clauses.stream()
			.anyMatch(c -> c.accepts(bsn, version));
	}

	/**
	 * The runtime artifacts of a workspace, or {@code null} when it has no bndrun to tell from
	 * (then nothing is classified).
	 */
	static RuntimeArtifacts of(Workspace workspace) throws Exception {
		List<File> files = new ResolveCheck(workspace).bndruns();
		if (files.isEmpty()) {
			return null;
		}
		record Run(String name, boolean sbom, List<Clause> clauses) {}
		List<Run> runs = new ArrayList<>();
		for (File file : files) {
			try (Bndrun run = Bndrun.createBndrun(workspace, file)) {
				List<Clause> clauses = new ArrayList<>();
				for (String instruction : INSTRUCTIONS) {
					clauses.addAll(clauses(run.mergeProperties(instruction)));
				}
				runs.add(new Run(workspace.getBase()
					.toPath()
					.relativize(file.toPath())
					.toString(), run.getProperty(SBOM) != null, clauses));
			} catch (Exception e) {
				// a broken bndrun tells nothing about the application
			}
		}
		List<Run> application = runs.stream()
			.filter(Run::sbom)
			.toList();
		if (application.isEmpty()) {
			application = runs.stream()
				.filter(r -> !isTestRun(r.clauses()))
				.toList();
		}
		List<Clause> clauses = new ArrayList<>();
		application.forEach(r -> clauses.addAll(r.clauses()));
		return new RuntimeArtifacts(clauses, application.stream()
			.map(Run::name)
			.toList());
	}

	static boolean isTestRun(List<Clause> clauses) {
		return clauses.stream()
			.anyMatch(c -> TEST_BUNDLES.stream()
				.anyMatch(t -> c.bsn()
					.equals(t)
					|| c.bsn()
						.startsWith(t + ".")
					|| c.bsn()
						.startsWith(t + "-")));
	}

	/** {@code bsn;version=range,…} as clauses; a version that is no range accepts every version. */
	static List<Clause> clauses(String value) {
		List<Clause> clauses = new ArrayList<>();
		if (value == null || value.isBlank()) {
			return clauses;
		}
		for (Map.Entry<String, Attrs> entry : new Parameters(value).entrySet()) {
			String bsn = Processor.removeDuplicateMarker(entry.getKey())
				.trim();
			if (bsn.isEmpty()) {
				continue;
			}
			clauses.add(new Clause(bsn, range(entry.getValue()
				.getVersion())));
		}
		return clauses;
	}

	/** {@code snapshot}, {@code latest}, {@code file}, or none: any version */
	private static final Set<String> ANY = Set.of("snapshot", "latest", "file", "project", "hash");

	private static VersionRange range(String version) {
		if (version == null) {
			return null;
		}
		String v = version.replace("'", "")
			.replace("\"", "")
			.trim();
		if (v.isEmpty() || ANY.contains(v) || !VersionRange.isVersionRange(v)) {
			return null;
		}
		return VersionRange.parseVersionRange(v);
	}
}
