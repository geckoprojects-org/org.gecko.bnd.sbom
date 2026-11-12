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
package org.gecko.bnd.update.gradle;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

import org.gradle.testkit.runner.BuildResult;
import org.gradle.testkit.runner.GradleRunner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Runs the tasks on a minimal bnd workspace (cnf with one Maven index) with the CLI jar built in
 * the bnd workspace (system property bnd.update.cli). Needs network access to Maven Central.
 */
public class BndUpdatePluginFunctionalTest {

	@TempDir
	Path	workspace;
	String	cli;

	@BeforeEach
	public void setUp() throws Exception {
		cli = System.getProperty("bnd.update.cli");
		assumeTrue(cli != null && new File(cli).isFile(), "the bnd-update CLI jar is needed: " + cli);
		Files.writeString(workspace.resolve("settings.gradle"), "rootProject.name = 'ws'\n");
		Files.writeString(workspace.resolve("build.gradle"), """
			plugins { id 'org.geckoprojects.bnd.update' }
			bndUpdate {
			    cliJar.from('%s')
			    scope = 'micro'
			}
			""".formatted(cli.replace("\\", "/")));
		Path cnf = Files.createDirectories(workspace.resolve("cnf"));
		Files.writeString(cnf.resolve("build.bnd"), """
			-plugin.central: aQute.bnd.repository.maven.provider.MavenBndRepository;\\
			    releaseUrl=https://repo.maven.apache.org/maven2/;\\
			    index=${.}/central.mvn;\\
			    readOnly=true;\\
			    name=Central
			""");
		Files.writeString(cnf.resolve("central.mvn"), "org.slf4j:slf4j-api:2.0.17\n");
	}

	private BuildResult run(String... args) {
		return GradleRunner.create()
			.withProjectDir(workspace.toFile())
			.withPluginClasspath()
			.withArguments(args)
			.forwardOutput()
			.build();
	}

	@Test
	public void updatesListsNewerVersionsWithinThePolicy() throws Exception {
		run("bndUpdates");

		String report = Files.readString(workspace.resolve("build/bnd-update/updates.md"));
		assertThat(report).contains("`org.slf4j:slf4j-api`")
			.contains("| 2.0.17 |")
			.contains("micro");
	}

	@Test
	public void applyChangesTheIndexInPlace() throws Exception {
		run("bndApply", "-PunusedToAvoidCache");

		assertThat(Files.readString(workspace.resolve("cnf/central.mvn"))).startsWith("org.slf4j:slf4j-api:2.0.")
			.doesNotContain("2.0.17");
		assertThat(Files.readString(workspace.resolve("build/bnd-update/apply.md"))).contains("Applied updates");
	}

	@Test
	public void vulnerabilitiesNeedsAReport() {
		BuildResult result = GradleRunner.create()
			.withProjectDir(workspace.toFile())
			.withPluginClasspath()
			.withArguments("bndVulnerabilities")
			.buildAndFail();

		assertThat(result.getOutput()).contains("bndVulnerabilities needs bndUpdate.trivyReport");
	}
}
