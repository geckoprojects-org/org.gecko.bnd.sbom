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

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.Map;
import java.util.Properties;

import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.artifacts.Configuration;
import org.gradle.api.tasks.TaskProvider;

/**
 * bnd update for a bnd workspace built with Gradle. Applied to the root project, it adds
 * <ul>
 * <li>{@code bndUpdates} — newer versions of the libraries in the {@code .mvn} indexes</li>
 * <li>{@code bndVulnerabilities} — fixes for a Trivy report</li>
 * <li>{@code bndResolveCheck} — does every bndrun still resolve?</li>
 * <li>{@code bndApply} — applies the updates, verifies them, reverts what fails (changes files)</li>
 * </ul>
 * configured through {@code bndUpdate { ... }}. The tasks run the bnd-update CLI; see
 * docs/bnd-update.md of org.gecko.bnd.sbom.
 */
public class BndUpdatePlugin implements Plugin<Project> {

	public static final String	EXTENSION		= "bndUpdate";
	public static final String	CONFIGURATION	= "bndUpdateCli";
	static final String			GROUP			= "bnd update";

	@Override
	public void apply(Project project) {
		BndUpdateExtension extension = project.getExtensions()
			.create(EXTENSION, BndUpdateExtension.class);
		extension.getFormat()
			.convention("markdown");
		extension.getMode()
			.convention("each");
		extension.getFailOnFindings()
			.convention(false);
		extension.getCliVersion()
			.convention(pluginVersion());
		extension.getOutputDirectory()
			.convention(project.getLayout()
				.getBuildDirectory()
				.dir("bnd-update"));

		Configuration cli = project.getConfigurations()
			.create(CONFIGURATION, c -> {
				c.setDescription("The bnd-update CLI");
				c.setCanBeConsumed(false);
				c.setTransitive(false);
				c.defaultDependencies(deps -> deps.add(project.getDependencies()
					.create("org.geckoprojects.bnd:org.gecko.bnd.update.cli:" + extension.getCliVersion()
						.get())));
			});

		register(project, extension, cli, "bndUpdates", "updates",
			"Lists newer versions of the libraries in the workspace's .mvn indexes.", false);
		register(project, extension, cli, "bndVulnerabilities", "vulnerabilities",
			"For each library of the Trivy report (bndUpdate.trivyReport), the smallest version that fixes it within the policy.",
			false);
		register(project, extension, cli, "bndResolveCheck", "resolve",
			"Resolves every bndrun of the workspace without writing and reports what changes or does not resolve.",
			true);
		register(project, extension, cli, "bndApply", "apply",
			"CHANGES FILES: applies the updates, resolves every bndrun, writes -runbundles, reverts what fails.", true);
	}

	private static void register(Project project, BndUpdateExtension extension, Configuration cli, String name,
		String command, String description, boolean needsBuiltBundles) {
		TaskProvider<BndUpdateTask> task = project.getTasks()
			.register(name, BndUpdateTask.class, t -> {
				t.setGroup(GROUP);
				t.setDescription(description);
				t.getCli()
					.from(extension.getCliJar()
						.getElements()
						.flatMap(files -> files.isEmpty() ? project.provider(() -> cli.getFiles())
							: project.provider(() -> extension.getCliJar()
								.getFiles())));
				t.getCommand()
					.set(command);
				t.getWorkspace()
					.set(project.getLayout()
						.getProjectDirectory());
				t.getScope()
					.set(extension.getScope());
				t.getMode()
					.set(extension.getMode());
				t.getOnly()
					.set(extension.getOnly());
				t.getBuildCommand()
					.set(extension.getBuildCommand());
				// only the commands that read them: an input a task does not use would still make
				// Gradle demand an ordering with whatever task writes it
				if (command.equals("vulnerabilities") || command.equals("apply")) {
					t.getTrivyReport()
						.set(extension.getTrivyReport());
					t.getSbom()
						.set(extension.getSbom());
				}
				t.getFormat()
					.set(extension.getFormat());
				t.getFailOnFindings()
					.set(extension.getFailOnFindings());
				t.getReport()
					.set(extension.getOutputDirectory()
						.zip(extension.getFormat(), (dir, format) -> dir.file(command + "." + extension(format))));
			});
		if (needsBuiltBundles) {
			// bndruns that run the workspace's own bundles resolve only when those are built
			project.getSubprojects()
				.forEach(sub -> task.configure(t -> t.dependsOn(sub.getTasks()
					.matching(other -> other.getName()
						.equals("jar")))));
		}
	}

	/** The plugin's own version: by default it runs the CLI of the same release. */
	static String pluginVersion() {
		try (InputStream in = BndUpdatePlugin.class.getResourceAsStream("plugin.properties")) {
			Properties properties = new Properties();
			if (in != null) {
				properties.load(in);
			}
			return properties.getProperty("version", "0.1.0-SNAPSHOT");
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

	private static String extension(String format) {
		return Map.of("json", "json", "markdown", "md")
			.getOrDefault(format, "txt");
	}
}
