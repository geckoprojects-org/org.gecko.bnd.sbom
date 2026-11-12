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
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.osgi.resource.Requirement;
import org.osgi.service.resolver.ResolutionException;

import aQute.bnd.build.Project;
import aQute.bnd.build.Workspace;
import aQute.bnd.build.model.clauses.VersionedClause;
import aQute.bnd.header.Attrs;
import aQute.bnd.header.Parameters;
import aQute.bnd.osgi.Constants;
import aQute.bnd.osgi.Processor;
import aQute.bnd.osgi.resource.FilterParser;
import aQute.bnd.osgi.resource.ResourceUtils;
import aQute.bnd.osgi.resource.ResourceUtils.IdentityCapability;
import biz.aQute.resolve.Bndrun;
import biz.aQute.resolve.RunResolution;

/**
 * Resolves the bndruns of a workspace with bnd's resolver and compares the result with the
 * {@code -runbundles} in the files. Writes nothing.
 * <p>
 * This is the safety check after an update of a {@code .mvn} index or a {@code -buildpath}
 * version: an update can make a bndrun unresolvable — a bundle's import range no longer
 * accepts the new provider — or change what other bndruns resolve to. Every bndrun has to
 * resolve before the update is committed. When one does not, the result lists the
 * requirements nothing satisfies — exactly the import, bundle or capability that blocks it.
 */
public final class ResolveCheck {

	private final Workspace workspace;

	public ResolveCheck(Workspace workspace) {
		this.workspace = workspace;
	}

	/** The bndrun files of all projects of the workspace (top level of each project), sorted. */
	public List<File> bndruns() throws Exception {
		List<File> bndruns = new ArrayList<>();
		for (Project project : workspace.getAllProjects()) {
			File[] files = project.getBase()
				.listFiles((dir, name) -> name.endsWith(".bndrun"));
			if (files != null) {
				bndruns.addAll(Arrays.asList(files));
			}
		}
		bndruns.sort(Comparator.naturalOrder());
		return bndruns;
	}

	/** Resolves every bndrun of the workspace. */
	public ResolveReport resolveAll() throws Exception {
		return resolve(bndruns());
	}

	public ResolveReport resolve(List<File> bndruns) {
		List<BndrunResult> results = new ArrayList<>();
		for (File bndrun : bndruns) {
			results.add(resolve(bndrun));
		}
		return new ResolveReport(results);
	}

	public BndrunResult resolve(File file) {
		String name = workspace.getBase()
			.toPath()
			.relativize(file.toPath())
			.toString();
		try (Bndrun run = Bndrun.createBndrun(workspace, file)) {
			List<String> current = clauses(run.getProperty(Constants.RUNBUNDLES));
			RunResolution resolution = run.resolve();
			if (!resolution.isOK()) {
				List<String> unresolved = new ArrayList<>();
				if (resolution.exception instanceof ResolutionException re) {
					FilterParser parser = new FilterParser();
					for (Requirement requirement : re.getUnresolvedRequirements()) {
						unresolved.add(who(requirement) + " -> " + requirement.getNamespace() + ": "
							+ parser.parse(requirement));
					}
				}
				return new BndrunResult(name, BndrunResult.Status.FAILED, current, List.of(), List.of(), List.of(),
					unresolved, firstLine(resolution.report(false)));
			}
			List<String> resolved = new ArrayList<>();
			for (VersionedClause clause : resolution.getRunBundles()) {
				resolved.add(clause.getName() + ";version=" + normalize(clause.getVersionRange()));
			}
			List<String> added = minus(resolved, current);
			List<String> removed = minus(current, resolved);
			BndrunResult.Status status = added.isEmpty() && removed.isEmpty() ? BndrunResult.Status.UNCHANGED
				: BndrunResult.Status.CHANGED;
			return new BndrunResult(name, status, current, resolved, added, removed, List.of(), null);
		} catch (Exception e) {
			return new BndrunResult(name, BndrunResult.Status.ERROR, List.of(), List.of(), List.of(), List.of(),
				List.of(), String.valueOf(e));
		}
	}

	/** {@code -runbundles} as {@code bsn;version=range}, in file order. */
	static List<String> clauses(String runbundles) {
		List<String> clauses = new ArrayList<>();
		if (runbundles == null || runbundles.isBlank()) {
			return clauses;
		}
		for (Map.Entry<String, Attrs> entry : new Parameters(runbundles).entrySet()) {
			String bsn = Processor.removeDuplicateMarker(entry.getKey());
			clauses.add(bsn + ";version=" + normalize(entry.getValue()
				.getVersion()));
		}
		return clauses;
	}

	/** quotes and blanks are irrelevant to the comparison */
	private static String normalize(String range) {
		return range == null ? "" : range.replace("'", "")
			.replace("\"", "")
			.replace(" ", "");
	}

	private static List<String> minus(List<String> a, List<String> b) {
		Set<String> result = new LinkedHashSet<>(a);
		b.forEach(result::remove);
		return new ArrayList<>(result);
	}

	private static String who(Requirement requirement) {
		if (requirement.getResource() == null) {
			return "-runrequires";
		}
		IdentityCapability identity = ResourceUtils.getIdentityCapability(requirement.getResource());
		// the resolver's synthetic resource for -runrequires is called <<INITIAL>>, without version
		if (identity == null || identity.version() == null || identity.osgi_identity()
			.startsWith("<<")) {
			return "-runrequires";
		}
		return identity.osgi_identity() + " " + identity.version();
	}

	private static String firstLine(String text) {
		if (text == null) {
			return null;
		}
		String trimmed = text.strip();
		int newline = trimmed.indexOf('\n');
		return newline < 0 ? trimmed : trimmed.substring(0, newline);
	}
}
