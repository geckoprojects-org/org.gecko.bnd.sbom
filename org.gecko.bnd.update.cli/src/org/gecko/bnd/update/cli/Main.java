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
package org.gecko.bnd.update.cli;

import java.io.File;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.gecko.bnd.update.AppliedUpdate;
import org.gecko.bnd.update.ApplyReport;
import org.gecko.bnd.update.BndrunResult;
import org.gecko.bnd.update.BuildStep;
import org.gecko.bnd.update.CheckReport;
import org.gecko.bnd.update.Proposal;
import org.gecko.bnd.update.ResolveCheck;
import org.gecko.bnd.update.ResolveReport;
import org.gecko.bnd.update.Sbom;
import org.gecko.bnd.update.Scope;
import org.gecko.bnd.update.TrivyReport;
import org.gecko.bnd.update.Update;
import org.gecko.bnd.update.UpdateApplier;
import org.gecko.bnd.update.UpdateFinder;
import org.gecko.bnd.update.VersionPolicy;
import org.gecko.bnd.update.VulnerabilityCheck;
import org.gecko.bnd.update.report.Reports;

import aQute.bnd.build.Workspace;
import aQute.lib.io.IO;

/**
 * Command line of the bnd update library. {@code updates}, {@code vulnerabilities} and
 * {@code resolve} only read; {@code apply} changes the {@code .mvn} indexes and the bndruns.
 *
 * <pre>
 * bnd-update updates         [--workspace DIR] [--scope micro|minor|major] [--format text|json|markdown] [--output FILE]
 * bnd-update vulnerabilities --trivy FILE [--sbom FILE] [--against-updates]
 *                            [--workspace DIR] [--scope ...] [--format ...] [--output FILE]
 * bnd-update resolve         [--workspace DIR] [--format ...] [--output FILE]
 * bnd-update apply           [--only G:A,...] [--from-vulnerabilities FILE [--sbom FILE]] [--mode all|each]
 *                            [--build-command CMD] [--workspace DIR] [--scope ...] [--format ...] [--output FILE]
 * </pre>
 *
 * Exit codes — {@code updates}: 0 nothing to update, 1 updates within the policy.
 * {@code vulnerabilities}: 0 nothing vulnerable, 1 every vulnerable library has a fix within
 * the policy, 2 at least one has no fix within the policy (or none at all). {@code resolve}: 0
 * every bndrun resolves to its current -runbundles, 1 every bndrun resolves but some to other
 * -runbundles, 2 at least one does not resolve. 64 usage error,
 * 70 internal error.
 */
public final class Main {

	static final int	OK				= 0;
	static final int	ACTIONABLE		= 1;
	static final int	NOT_FIXABLE		= 2;
	static final int	USAGE			= 64;
	static final int	INTERNAL_ERROR	= 70;

	private final PrintStream	out;
	private final PrintStream	err;

	Main(PrintStream out, PrintStream err) {
		this.out = out;
		this.err = err;
	}

	public static void main(String[] args) {
		// bnd logs every repository download at INFO; a report tool only shows warnings, unless
		// the caller configures slf4j-simple otherwise
		if (System.getProperty("org.slf4j.simpleLogger.defaultLogLevel") == null) {
			System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "warn");
		}
		System.exit(new Main(System.out, System.err).run(args));
	}

	int run(String[] args) {
		if (args.length == 0 || args[0].equals("--help") || args[0].equals("-h")) {
			usage();
			return args.length == 0 ? USAGE : OK;
		}
		Map<String, String> options;
		try {
			options = options(args);
		} catch (IllegalArgumentException e) {
			err.println(e.getMessage());
			usage();
			return USAGE;
		}
		try {
			return switch (args[0]) {
				case "updates" -> updates(options);
				case "vulnerabilities" -> vulnerabilities(options);
				case "resolve" -> resolve(options);
				case "apply" -> apply(options);
				default -> {
					err.println("Unknown command: " + args[0]);
					usage();
					yield USAGE;
				}
			};
		} catch (IllegalArgumentException e) {
			err.println(e.getMessage());
			return USAGE;
		} catch (Exception e) {
			err.println("Failed: " + e);
			return INTERNAL_ERROR;
		}
	}

	private int updates(Map<String, String> options) throws Exception {
		try (Workspace workspace = workspace(options)) {
			List<Update> updates = UpdateFinder.forWorkspace(workspace)
				.withPolicy(policy(workspace, options))
				.find();
			report(workspace, options, switch (format(options)) {
				case "json" -> Reports.json(updates);
				case "markdown" -> Reports.markdown(updates);
				default -> text(updates);
			});
			return updates.stream()
				.anyMatch(Update::isProposed) ? ACTIONABLE : OK;
		}
	}

	private int vulnerabilities(Map<String, String> options) throws Exception {
		String trivyFile = options.get("trivy");
		if (trivyFile == null) {
			throw new IllegalArgumentException("vulnerabilities needs --trivy FILE");
		}
		try (Workspace workspace = workspace(options)) {
			VersionPolicy policy = policy(workspace, options);
			VulnerabilityCheck check = options.containsKey("against-updates")
				? VulnerabilityCheck.againstUpdates(UpdateFinder.forWorkspace(workspace)
					.withPolicy(policy)
					.find(), policy)
				: VulnerabilityCheck.forWorkspace(workspace)
					.withPolicy(policy);
			TrivyReport trivy;
			try (InputStream in = IO.stream(new File(trivyFile))) {
				trivy = TrivyReport.read(in);
			}
			Sbom sbom = null;
			if (options.containsKey("sbom")) {
				try (InputStream in = IO.stream(new File(options.get("sbom")))) {
					sbom = Sbom.read(in);
				}
			}
			CheckReport report = check.check(sbom, trivy);
			report(workspace, options, switch (format(options)) {
				case "json" -> Reports.json(report);
				case "markdown" -> Reports.markdown(report);
				default -> text(report);
			});
			if (report.proposals()
				.isEmpty()) {
				return OK;
			}
			boolean allFixable = report.proposals()
				.stream()
				.allMatch(p -> p.status() == Proposal.Status.UPDATE);
			return allFixable ? ACTIONABLE : NOT_FIXABLE;
		}
	}

	private int resolve(Map<String, String> options) throws Exception {
		try (Workspace workspace = workspace(options)) {
			ResolveReport report = new ResolveCheck(workspace).resolveAll();
			report(workspace, options, switch (format(options)) {
				case "json" -> Reports.json(report);
				case "markdown" -> Reports.markdown(report);
				default -> text(report);
			});
			if (!report.allResolve()) {
				return NOT_FIXABLE;
			}
			return report.withStatus(BndrunResult.Status.CHANGED)
				.isEmpty() ? OK : ACTIONABLE;
		}
	}

	private int apply(Map<String, String> options) throws Exception {
		File dir;
		List<Update> updates;
		try (Workspace workspace = workspace(options)) {
			dir = workspace.getBase();
			VersionPolicy policy = policy(workspace, options);
			UpdateFinder finder = UpdateFinder.forWorkspace(workspace)
				.withPolicy(policy);
			if (options.containsKey("from-vulnerabilities")) {
				TrivyReport trivy;
				try (InputStream in = IO.stream(new File(options.get("from-vulnerabilities")))) {
					trivy = TrivyReport.read(in);
				}
				Sbom sbom = null;
				if (options.containsKey("sbom")) {
					try (InputStream in = IO.stream(new File(options.get("sbom")))) {
						sbom = Sbom.read(in);
					}
				}
				updates = finder.forProposals(VulnerabilityCheck.forWorkspace(workspace)
					.withPolicy(policy)
					.check(sbom, trivy)
					.proposals());
			} else {
				updates = finder.find();
			}
		}
		String only = options.get("only");
		if (only != null) {
			List<Pattern> patterns = new ArrayList<>();
			for (String p : only.split(",")) {
				if (!p.isBlank()) {
					patterns.add(Pattern.compile(Pattern.quote(p.trim())
						.replace("*", "\\E[^:]*\\Q")));
				}
			}
			updates = updates.stream()
				.filter(u -> patterns.stream()
					.anyMatch(p -> p.matcher(u.library()
						.ga())
						.matches()))
				.toList();
		}
		UpdateApplier.Mode mode = switch (options.getOrDefault("mode", "all")) {
			case "all" -> UpdateApplier.Mode.ALL;
			case "each" -> UpdateApplier.Mode.EACH;
			default -> throw new IllegalArgumentException("Unknown mode '" + options.get("mode") + "', expected all or each");
		};
		String command = options.get("build-command");
		ApplyReport report = new UpdateApplier(dir, command != null ? BuildStep.command(command) : null).apply(updates,
			mode);
		String content = switch (format(options)) {
			case "json" -> Reports.json(report);
			case "markdown" -> Reports.markdown(report);
			default -> text(report);
		};
		String output = options.get("output");
		if (output == null) {
			out.print(content);
		} else {
			Files.writeString(new File(output).toPath(), content, StandardCharsets.UTF_8);
		}
		if (report.baselineFails()) {
			err.println("No update applied: the workspace does not resolve even without updates;"
				+ " build its bundles first (e.g. ./gradlew assemble)");
			return NOT_FIXABLE;
		}
		if (report.anyReverted()) {
			return NOT_FIXABLE;
		}
		return report.anyApplied() ? ACTIONABLE : OK;
	}

	private static String text(ApplyReport report) {
		StringBuilder text = new StringBuilder();
		for (AppliedUpdate a : report.updates()) {
			text.append(String.format("%-60s %-16s -> %-16s %s%s%n", a.update()
				.library()
				.ga(),
				a.update()
					.library()
					.version(),
				a.update()
					.proposed() != null ? a.update()
						.proposed()
						: "(" + a.update()
							.latest() + ")",
				a.status(), a.reason() != null ? "  " + a.reason()
					.lines()
					.findFirst()
					.orElse("") : ""));
		}
		return text.length() == 0 ? "No update to apply.\n" : text.toString();
	}

	private static String text(ResolveReport report) {
		StringBuilder text = new StringBuilder();
		for (BndrunResult r : report.results()) {
			text.append(String.format("%-70s %s%n", r.bndrun(), switch (r.status()) {
				case UNCHANGED -> "unchanged";
				case CHANGED -> "changed (+" + r.added()
					.size() + " -" + r.removed()
						.size()
					+ ")";
				case FAILED -> "DOES NOT RESOLVE";
				case ERROR -> "ERROR " + r.message();
			}));
			r.unresolved()
				.forEach(u -> text.append("    unresolved: ")
					.append(u)
					.append(System.lineSeparator()));
		}
		return text.length() == 0 ? "No bndrun.\n" : text.toString();
	}

	private static String text(List<Update> updates) {
		StringBuilder text = new StringBuilder();
		for (Update u : updates) {
			text.append(String.format("%-60s %-16s -> %-16s (allowed %s, latest %s)%n", u.library()
				.ga(), u.library()
					.version(),
				u.isProposed() ? u.proposed() : "-", u.allowed()
					.id(),
				u.latest()));
		}
		return text.length() == 0 ? "No updates.\n" : text.toString();
	}

	private static String text(CheckReport report) {
		StringBuilder text = new StringBuilder();
		for (Proposal p : report.proposals()) {
			text.append(String.format("%-60s %-16s %2d vulnerabilities  %s%n", p.library()
				.ga(), p.library()
					.version(),
				p.vulnerabilities()
					.size(),
				switch (p.status()) {
					case UPDATE -> "-> " + p.proposed() + " (" + p.allowed()
						.id() + ")";
					case OUTSIDE_POLICY -> "needs a " + p.needed()
						.id() + " update";
					case NO_FIX -> "no fix available";
				}));
		}
		return text.length() == 0 ? "No vulnerable library.\n" : text.toString();
	}

	private Workspace workspace(Map<String, String> options) throws Exception {
		File dir = new File(options.getOrDefault("workspace", "."))
			.getAbsoluteFile();
		if (!new File(dir, Workspace.CNFDIR).isDirectory()) {
			throw new IllegalArgumentException("Not a bnd workspace (no cnf directory): " + dir);
		}
		return new Workspace(dir);
	}

	private static VersionPolicy policy(Workspace workspace, Map<String, String> options) {
		VersionPolicy policy = VersionPolicy.from(workspace);
		String scope = options.get("scope");
		return scope != null ? policy.withDefault(Scope.parse(scope)) : policy;
	}

	private static String format(Map<String, String> options) {
		String format = options.getOrDefault("format", "text");
		if (!List.of("text", "json", "markdown")
			.contains(format)) {
			throw new IllegalArgumentException("Unknown format '" + format + "', expected text, json or markdown");
		}
		return format;
	}

	private void report(Workspace workspace, Map<String, String> options, String content) throws Exception {
		workspace.getErrors()
			.forEach(e -> err.println("error: " + e));
		workspace.getWarnings()
			.forEach(w -> err.println("warning: " + w));
		String output = options.get("output");
		if (output == null) {
			out.print(content);
		} else {
			Files.writeString(new File(output).toPath(), content, StandardCharsets.UTF_8);
		}
	}

	/** {@code --name value} pairs after the command; {@code --against-updates} is a flag. */
	static Map<String, String> options(String[] args) {
		Map<String, String> options = new LinkedHashMap<>();
		List<String> flags = List.of("against-updates");
		List<String> known = List.of("workspace", "scope", "format", "output", "trivy", "sbom", "only",
			"from-vulnerabilities", "mode", "build-command");
		List<String> rest = new ArrayList<>(List.of(args)
			.subList(1, args.length));
		for (int i = 0; i < rest.size(); i++) {
			String arg = rest.get(i);
			if (!arg.startsWith("--")) {
				throw new IllegalArgumentException("Unexpected argument: " + arg);
			}
			String name = arg.substring(2);
			if (flags.contains(name)) {
				options.put(name, "true");
			} else if (known.contains(name)) {
				if (i + 1 >= rest.size()) {
					throw new IllegalArgumentException("Missing value for --" + name);
				}
				options.put(name, rest.get(++i));
			} else {
				throw new IllegalArgumentException("Unknown option: --" + name);
			}
		}
		return options;
	}

	private void usage() {
		err.println("""
			Usage:
			  bnd-update updates         [--workspace DIR] [--scope micro|minor|major] [--format text|json|markdown] [--output FILE]
			  bnd-update vulnerabilities --trivy FILE [--sbom FILE] [--against-updates]
			                             [--workspace DIR] [--scope micro|minor|major] [--format text|json|markdown] [--output FILE]
			  bnd-update resolve         [--workspace DIR] [--format text|json|markdown] [--output FILE]
			  bnd-update apply           [--only G:A,...] [--from-vulnerabilities FILE [--sbom FILE]] [--mode all|each]
			                             [--build-command CMD] [--workspace DIR] [--scope micro|minor|major] [--format ...] [--output FILE]

			updates          newer versions of the libraries in the workspace's .mvn indexes,
			                 the proposal is the highest version the version policy allows
			vulnerabilities  for each library in a Trivy JSON report, the smallest available version
			                 within the policy that fixes all its vulnerabilities; --sbom adds where
			                 the library sits, --against-updates considers only the found updates
			resolve          resolves every bndrun of the workspace (writes nothing) and compares the
			                 result with the -runbundles in the files; lists unresolved requirements
			apply            CHANGES THE WORKSPACE: applies the proposed updates (all, --only some, or
			                 the fixes of a Trivy report) to the .mvn indexes, resolves every bndrun,
			                 writes the new -runbundles, runs --build-command; reverts what fails.
			                 --mode all: together, all or nothing; each: one by one, keeps what passes

			--scope overrides the default scope of the workspace's -update-policy (default micro).

			Exit codes: 0 nothing to do, 1 updates/fixes within the policy (resolve: some -runbundles
			change; apply: updates applied), 2 a vulnerability has no fix within the policy (resolve:
			a bndrun does not resolve; apply: an update was reverted), 64 usage error, 70 internal error.""");
	}
}
