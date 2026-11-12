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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.gradle.api.DefaultTask;
import org.gradle.api.GradleException;
import org.gradle.api.file.ConfigurableFileCollection;
import org.gradle.api.file.DirectoryProperty;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.provider.ListProperty;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Classpath;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.InputFile;
import org.gradle.api.tasks.Internal;
import org.gradle.api.tasks.Optional;
import org.gradle.api.tasks.OutputFile;
import org.gradle.api.tasks.PathSensitive;
import org.gradle.api.tasks.PathSensitivity;
import org.gradle.api.tasks.TaskAction;
import org.gradle.process.ExecOperations;
import org.gradle.process.ExecResult;

import javax.inject.Inject;

/**
 * Runs one command of the bnd-update CLI ({@code updates}, {@code vulnerabilities},
 * {@code resolve}, {@code apply}) on the bnd workspace, in its own JVM: the bnd Gradle plugin
 * already brings a bndlib into the build, a second one in the same classloader would be a
 * source of conflicts.
 * <p>
 * Exit codes 0 and 1 are results (nothing to do / something to act on), 2 a finding that needs a
 * decision — it fails the task only with {@code failOnFindings}; everything else fails it.
 */
public abstract class BndUpdateTask extends DefaultTask {

	@Inject
	protected abstract ExecOperations getExecOperations();

	@Classpath
	public abstract ConfigurableFileCollection getCli();

	@Input
	public abstract Property<String> getCommand();

	@Internal
	public abstract DirectoryProperty getWorkspace();

	@Input
	@Optional
	public abstract Property<String> getScope();

	@Input
	@Optional
	public abstract Property<String> getMode();

	@Input
	@Optional
	public abstract ListProperty<String> getOnly();

	@Input
	@Optional
	public abstract Property<String> getBuildCommand();

	@InputFile
	@Optional
	@PathSensitive(PathSensitivity.NONE)
	public abstract RegularFileProperty getTrivyReport();

	@InputFile
	@Optional
	@PathSensitive(PathSensitivity.NONE)
	public abstract RegularFileProperty getSbom();

	@Input
	public abstract Property<String> getFormat();

	@OutputFile
	public abstract RegularFileProperty getReport();

	@Input
	public abstract Property<Boolean> getFailOnFindings();

	public BndUpdateTask() {
		// the result depends on the repositories, not only on the inputs
		getOutputs().upToDateWhen(task -> false);
	}

	@TaskAction
	public void run() {
		File report = getReport().get()
			.getAsFile();
		List<String> args = new ArrayList<>();
		String command = getCommand().get();
		args.add(command);
		args.add("--workspace");
		args.add(getWorkspace().get()
			.getAsFile()
			.getAbsolutePath());
		args.add("--format");
		args.add(getFormat().get());
		args.add("--output");
		args.add(report.getAbsolutePath());
		if (!command.equals("resolve") && getScope().isPresent()) {
			args.add("--scope");
			args.add(getScope().get());
		}
		switch (command) {
			case "vulnerabilities" -> {
				if (!getTrivyReport().isPresent()) {
					throw new GradleException("bndVulnerabilities needs bndUpdate.trivyReport");
				}
				args.add("--trivy");
				args.add(getTrivyReport().get()
					.getAsFile()
					.getAbsolutePath());
				addSbom(args);
			}
			case "apply" -> {
				args.add("--mode");
				args.add(getMode().getOrElse("each"));
				if (!getOnly().getOrElse(List.of())
					.isEmpty()) {
					args.add("--only");
					args.add(String.join(",", getOnly().get()));
				}
				if (getBuildCommand().isPresent()) {
					args.add("--build-command");
					args.add(getBuildCommand().get());
				}
				if (getTrivyReport().isPresent()) {
					args.add("--from-vulnerabilities");
					args.add(getTrivyReport().get()
						.getAsFile()
						.getAbsolutePath());
					addSbom(args);
				}
			}
			default -> {}
		}

		ByteArrayOutputStream err = new ByteArrayOutputStream();
		ExecResult result = getExecOperations().javaexec(spec -> {
			spec.classpath(getCli());
			spec.getMainClass()
				.set("org.gecko.bnd.update.cli.Main");
			spec.args(args);
			spec.setIgnoreExitValue(true);
			spec.setErrorOutput(err);
		});
		int exit = result.getExitValue();
		String stderr = err.toString()
			.strip();
		if (!stderr.isEmpty()) {
			getLogger().info(stderr);
		}
		getLogger().lifecycle("bnd update {}: exit {}, report {}", command, exit, report);
		switch (exit) {
			case 0, 1 -> {}
			case 2 -> {
				if (getFailOnFindings().get()) {
					throw new GradleException("bnd update " + command + " reports findings that need a decision; see " + report);
				}
				getLogger().warn("bnd update {}: findings that need a decision, see {}", command, report);
			}
			default -> throw new GradleException("bnd update " + command + " failed (exit " + exit + "): " + stderr);
		}
	}

	private void addSbom(List<String> args) {
		if (getSbom().isPresent()) {
			args.add("--sbom");
			args.add(getSbom().get()
				.getAsFile()
				.getAbsolutePath());
		}
	}
}
