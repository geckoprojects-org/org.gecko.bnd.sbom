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
package org.gecko.bnd.update.maven.plugin;

import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.Locale;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.gecko.bnd.update.CheckReport;
import org.gecko.bnd.update.Proposal;
import org.gecko.bnd.update.Sbom;
import org.gecko.bnd.update.Scope;
import org.gecko.bnd.update.TrivyReport;
import org.gecko.bnd.update.VersionPolicy;
import org.gecko.bnd.update.VulnerabilityCheck;
import org.gecko.bnd.update.report.Reports;

/**
 * For each library a Trivy report lists as vulnerable: the smallest version in the project's
 * Maven repositories that fixes all its vulnerabilities and lies within the version policy.
 * Reads only. The report goes to {@code target/bnd-update/vulnerabilities.md} (or {@code .json})
 * and the build log.
 * <p>
 * Changing the versions in the pom is Dependabot's or the developer's job; re-resolving the
 * bndruns afterwards is {@code bnd-resolver-maven-plugin}'s.
 */
@Mojo(name = "vulnerabilities", defaultPhase = LifecyclePhase.VERIFY, threadSafe = true)
public class VulnerabilitiesMojo extends AbstractMojo {

	/** Trivy JSON report ({@code trivy sbom --format json}). */
	@Parameter(property = "bnd-update.trivy", required = true)
	File							trivyReport;

	/** The CycloneDX SBOM the report was made from; adds where each library sits. */
	@Parameter(property = "bnd-update.sbom")
	File							sbom;

	/** Default scope: micro, minor or major. */
	@Parameter(property = "bnd-update.scope", defaultValue = "micro")
	String							scope;

	/**
	 * Per-library scopes in the {@code -update-policy} syntax, e.g.
	 * {@code com.fasterxml.jackson.core:*;scope=minor}.
	 */
	@Parameter(property = "bnd-update.policy")
	String							policy;

	/** markdown or json. */
	@Parameter(property = "bnd-update.format", defaultValue = "markdown")
	String							format;

	@Parameter(defaultValue = "${project.build.directory}/bnd-update")
	File							outputDirectory;

	/**
	 * When to fail the build: {@code none}; {@code unfixable} — a library has no fix within the
	 * policy; {@code vulnerable} — any library is vulnerable.
	 */
	@Parameter(property = "bnd-update.failOn", defaultValue = "none")
	String							failOn;

	@Parameter(property = "bnd-update.skip", defaultValue = "false")
	boolean							skip;

	@Parameter(defaultValue = "${project}", readonly = true, required = true)
	MavenProject					project;

	@Parameter(defaultValue = "${repositorySystemSession}", readonly = true, required = true)
	RepositorySystemSession			session;

	@Component
	RepositorySystem				repositorySystem;

	@Override
	public void execute() throws MojoExecutionException, MojoFailureException {
		if (skip) {
			getLog().info("bnd update: skipped");
			return;
		}
		CheckReport report;
		try {
			VersionPolicy versionPolicy = VersionPolicy.parse(policy)
				.withDefault(Scope.parse(scope));
			VulnerabilityCheck check = new VulnerabilityCheck(
				new MavenResolverVersions(repositorySystem, session, project.getRemoteProjectRepositories()),
				versionPolicy);
			TrivyReport trivy;
			try (InputStream in = Files.newInputStream(trivyReport.toPath())) {
				trivy = TrivyReport.read(in);
			}
			Sbom sbomModel = null;
			if (sbom != null) {
				try (InputStream in = Files.newInputStream(sbom.toPath())) {
					sbomModel = Sbom.read(in);
				}
			}
			report = check.check(sbomModel, trivy);
			boolean json = "json".equals(format.toLowerCase(Locale.ROOT));
			Files.createDirectories(outputDirectory.toPath());
			File output = new File(outputDirectory, json ? "vulnerabilities.json" : "vulnerabilities.md");
			Files.writeString(output.toPath(), json ? Reports.json(report) : Reports.markdown(report),
				StandardCharsets.UTF_8);
			log(report);
			getLog().info("bnd update: report written to " + output);
		} catch (IllegalArgumentException e) {
			throw new MojoExecutionException("bnd update: " + e.getMessage(), e);
		} catch (Exception e) {
			throw new MojoExecutionException("bnd update failed: " + e, e);
		}
		String failure = failure(report, failOn);
		if (failure != null) {
			throw new MojoFailureException("bnd update: " + failure);
		}
	}

	private void log(CheckReport report) {
		if (report.proposals()
			.isEmpty()) {
			getLog().info("bnd update: no vulnerable library");
			return;
		}
		for (Proposal p : report.proposals()) {
			String line = p.library() + ": " + p.vulnerabilities()
				.size() + " vulnerabilities, " + switch (p.status()) {
					case UPDATE -> "fixed by " + p.proposed() + " (" + p.allowed()
						.id() + ")";
					case OUTSIDE_POLICY -> "needs a " + p.needed()
						.id() + " update (allowed: " + p.allowed()
							.id()
						+ ")";
					case NO_FIX -> "no available version fixes all";
				};
			if (p.status() == Proposal.Status.UPDATE) {
				getLog().warn(line);
			} else {
				getLog().error(line);
			}
		}
	}

	/** The reason to fail the build, or {@code null}. */
	static String failure(CheckReport report, String failOn) {
		List<Proposal> proposals = report.proposals();
		return switch (failOn.toLowerCase(Locale.ROOT)) {
			case "none" -> null;
			case "vulnerable" -> proposals.isEmpty() ? null : proposals.size() + " vulnerable libraries";
			case "unfixable" -> {
				long unfixable = proposals.stream()
					.filter(p -> p.status() != Proposal.Status.UPDATE)
					.count();
				yield unfixable == 0 ? null : unfixable + " vulnerable libraries without a fix within the version policy";
			}
			default -> throw new IllegalArgumentException(
				"Unknown failOn '" + failOn + "', expected none, unfixable or vulnerable");
		};
	}
}
