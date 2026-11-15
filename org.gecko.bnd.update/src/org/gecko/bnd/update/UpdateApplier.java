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
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.gecko.bnd.update.maven.IndexEditor;
import org.osgi.resource.Resource;

import aQute.bnd.build.Workspace;
import aQute.bnd.repository.maven.provider.MavenBndRepository;
import biz.aQute.resolve.Bndrun;

/**
 * Applies updates to a workspace and proves the result: the version in the {@code .mvn} index is
 * changed, every bndrun is resolved again, the new {@code -runbundles} are written, and — if a
 * {@link BuildStep} is given — the workspace is built. An update that makes a bndrun unresolvable
 * or breaks the build is reverted; the files are then exactly as before.
 * <p>
 * Two modes:
 * <ul>
 * <li>{@link Mode#ALL}: all updates together, checked once; if the check fails, all are reverted.
 * Fast; right when the updates belong together (one PR).</li>
 * <li>{@link Mode#EACH}: one update after the other, each checked on top of the ones kept so far;
 * an update that fails is reverted and the next one is tried. Shows which update breaks what.</li>
 * </ul>
 * This changes files in the workspace — run it on a branch or a working copy. Libraries embedded in
 * workspace bundles ({@code -buildpath} versions) and pom indexes are not changed; they are
 * reported as {@link AppliedUpdate.Status#NOT_IN_INDEX}. Neither are indexes the workspace does not
 * own — those a {@code -library} brings along, expanded in the bnd cache: they are reported as
 * {@link AppliedUpdate.Status#READ_ONLY_INDEX}, naming the library.
 */
public final class UpdateApplier {

	public enum Mode {
		ALL,
		EACH
	}

	private final File		workspaceDir;
	private final BuildStep	build;

	/**
	 * @param workspaceDir the bnd workspace (contains {@code cnf})
	 * @param build the build to run after resolving, or {@code null} for none
	 */
	public UpdateApplier(File workspaceDir, BuildStep build) {
		this.workspaceDir = workspaceDir.getAbsoluteFile();
		this.build = build;
	}

	public ApplyReport apply(List<Update> updates, Mode mode) throws Exception {
		groups = List.of();
		lastSuccessfulBuild = null;
		List<AppliedUpdate> results = new ArrayList<>();
		List<Update> applicable = new ArrayList<>();
		for (Update update : updates) {
			if (!update.isProposed()) {
				results.add(new AppliedUpdate(update, AppliedUpdate.Status.NOT_PROPOSED,
					"no version within the " + update.allowed()
						.id() + " scope"));
			} else if (update.index() == null) {
				results.add(new AppliedUpdate(update, AppliedUpdate.Status.NOT_IN_INDEX,
					"not in a repository index: embedded in a workspace bundle - update the -buildpath of that bundle"));
			} else if (!origin(update).isWritable()) {
				results.add(new AppliedUpdate(update, AppliedUpdate.Status.READ_ONLY_INDEX, readOnly(update)));
			} else if (!indexFile(update).isFile() || update.index()
				.endsWith(".xml")) {
				results.add(new AppliedUpdate(update, AppliedUpdate.Status.NOT_IN_INDEX,
					"index " + update.index() + " is not a text index (.mvn); pom indexes are not changed"));
			} else {
				applicable.add(update);
			}
		}
		ResolveReport baseline = resolveAll();
		if (applicable.isEmpty()) {
			return new ApplyReport(mode, results, baseline, null, baseline);
		}
		// Every bndrun has to resolve before an update is tried; otherwise every update would
		// be blamed for a failure it did not cause.
		if (!baseline.allResolve()) {
			for (Update update : applicable) {
				results.add(new AppliedUpdate(update, AppliedUpdate.Status.NOT_APPLIED,
					"the workspace does not resolve without updates"));
			}
			return new ApplyReport(mode, results, baseline, null, baseline);
		}

		if (mode == Mode.ALL) {
			Snapshot snapshot = Snapshot.take(workspaceDir, applicable);
			List<AppliedUpdate> step = new ArrayList<>();
			for (Update update : applicable) {
				step.add(edit(update));
			}
			String failure = verify();
			if (failure != null) {
				snapshot.restore();
				for (AppliedUpdate a : step) {
					results.add(a.status() == AppliedUpdate.Status.APPLIED
						? new AppliedUpdate(a.update(), AppliedUpdate.Status.REVERTED, failure)
						: a);
				}
			} else {
				results.addAll(step);
			}
		} else {
			List<Update> reverted = new ArrayList<>();
			Map<Update, List<String>> unresolved = new LinkedHashMap<>();
			for (Update update : applicable) {
				Snapshot snapshot = Snapshot.take(workspaceDir, List.of(update));
				AppliedUpdate edited = edit(update);
				if (edited.status() != AppliedUpdate.Status.APPLIED) {
					results.add(edited);
					continue;
				}
				String failure = verify();
				if (failure != null) {
					snapshot.restore();
					results.add(new AppliedUpdate(update, AppliedUpdate.Status.REVERTED, failure));
					reverted.add(update);
					List<String> blamed = blamed(lastFailure);
					if (blamed != null) {
						unresolved.put(update, blamed);
					}
				} else {
					results.add(edited);
				}
			}
			groups = groups(reverted, unresolved);
		}
		// the last successful build is the one of the final state: every later update that
		// failed was reverted
		return new ApplyReport(mode, results, resolveAll(), lastSuccessfulBuild, baseline, groups);
	}

	private List<RevertedGroup>	groups		= List.of();
	/** the resolution of the last failed {@link #verify()}; {@code null} if the build failed */
	private ResolveReport		lastFailure;

	/**
	 * The unresolved requirements of a failed check, for grouping; {@code null} when the failure
	 * has another cause: the build failed, or a {@code -runfw}/{@code -runpath} pin matches
	 * nothing.
	 */
	private static List<String> blamed(ResolveReport failure) {
		if (failure == null) {
			return null;
		}
		List<String> blamed = new ArrayList<>();
		for (BndrunResult r : failure.results()) {
			if (r.resolves()) {
				continue;
			}
			if (!r.missing()
				.isEmpty()) {
				return null;
			}
			blamed.addAll(r.unresolved());
		}
		return blamed.isEmpty() ? null : blamed;
	}

	/** The groups among the reverted updates; reads the repositories for the installed bundles. */
	private List<RevertedGroup> groups(List<Update> reverted, Map<Update, List<String>> unresolved) throws Exception {
		if (unresolved.size() < 2) {
			return List.of();
		}
		try (Workspace workspace = new Workspace(workspaceDir)) {
			List<Resource> resources = new ArrayList<>();
			for (MavenBndRepository repository : workspace.getPlugins(MavenBndRepository.class)) {
				resources.addAll(repository.getResources());
			}
			return RevertedGroups.of(reverted, unresolved,
				RevertedGroups.installed(unresolved.keySet(), resources));
		}
	}

	private BuildStep.Result lastSuccessfulBuild;

	private AppliedUpdate edit(Update update) throws Exception {
		IndexEditor.Result result = IndexEditor.replace(indexFile(update), update.library()
			.groupId(),
			update.library()
				.artifactId(),
			update.library()
				.version(),
			update.proposed()
				.toString());
		if (result.replaced() > 0) {
			return new AppliedUpdate(update, AppliedUpdate.Status.APPLIED, null);
		}
		if (result.macro() > 0) {
			return new AppliedUpdate(update, AppliedUpdate.Status.SKIPPED_MACRO,
				"the version in " + update.index() + " is a macro");
		}
		return new AppliedUpdate(update, AppliedUpdate.Status.NOT_IN_INDEX,
			"no line " + update.library() + " in " + update.index());
	}

	/**
	 * Resolves every bndrun with the changed indexes; if all resolve, writes the new
	 * -runbundles and runs the build. Returns {@code null} on success, otherwise the reason.
	 */
	private String verify() throws Exception {
		lastFailure = null;
		ResolveReport report = resolveAll();
		if (!report.allResolve()) {
			lastFailure = report;
			return report.results()
				.stream()
				.filter(r -> !r.resolves())
				.map(UpdateApplier::failure)
				.collect(Collectors.joining("\n"));
		}
		writeRunbundles(report);
		if (build != null) {
			BuildStep.Result result = build.build(workspaceDir);
			if (!result.ok()) {
				return "the build failed:\n" + result.output();
			}
			lastSuccessfulBuild = result;
		}
		return null;
	}

	/**
	 * Why a bndrun no longer resolves. A {@code -runfw} or {@code -runpath} entry that matches
	 * nothing comes first: every bndrun resolved before the update, so the update removed the
	 * version it pins, and the unresolved requirements are only the consequence.
	 */
	static String failure(BndrunResult r) {
		StringBuilder reason = new StringBuilder(r.bndrun()).append(" does not resolve");
		if (!r.missing()
			.isEmpty()) {
			reason.append(": ")
				.append(r.missing()
					.stream()
					.map(m -> m + " pins a version the update removes")
					.collect(Collectors.joining("; ")));
			if (!r.unresolved()
				.isEmpty()) {
				reason.append(" (therefore unresolved: ")
					.append(String.join("; ", r.unresolved()))
					.append(")");
			}
		} else if (!r.unresolved()
			.isEmpty()) {
			reason.append(": ")
				.append(String.join("; ", r.unresolved()));
		} else if (r.message() != null) {
			reason.append(": ")
				.append(r.message());
		}
		return reason.toString();
	}

	/** A fresh workspace each time: bnd caches the indexes it has read. */
	private ResolveReport resolveAll() throws Exception {
		try (Workspace workspace = new Workspace(workspaceDir)) {
			return new ResolveCheck(workspace).resolveAll();
		}
	}

	private void writeRunbundles(ResolveReport report) throws Exception {
		try (Workspace workspace = new Workspace(workspaceDir)) {
			for (BndrunResult result : report.withStatus(BndrunResult.Status.CHANGED)) {
				try (Bndrun run = Bndrun.createBndrun(workspace, new File(workspaceDir, result.bndrun()))) {
					run.resolve(false, true);
				}
			}
		}
	}

	/**
	 * Who owns the index of an update. The finder's verdict counts, but the file is checked as
	 * well: whatever the caller says, nothing in the bnd cache is written.
	 */
	private IndexOrigin origin(Update update) {
		IndexOrigin reported = update.origin() != null ? update.origin() : IndexOrigin.WORKSPACE;
		if (!reported.isWritable()) {
			return reported;
		}
		return IndexOrigin.of(indexFile(update), workspaceDir,
			new File(workspaceDir, Workspace.CNFDIR + "/" + UpdateFinder.CACHE));
	}

	private String readOnly(Update update) {
		IndexOrigin origin = origin(update);
		return switch (origin.kind()) {
			case LIBRARY -> "the index " + update.index() + " comes with the bnd library " + origin.source()
				+ " (-library), not from the workspace - update the library to get a newer version";
			default -> "the index " + update.index() + " is not part of the workspace (" + origin.source()
				+ ") and is not changed";
		};
	}

	/** The index of an update; a relative path is relative to the workspace. */
	private File indexFile(Update update) {
		File file = new File(update.index());
		return file.isAbsolute() ? file : new File(workspaceDir, update.index());
	}

	/** The content of the files an update may change, to restore them on failure. */
	private record Snapshot(Map<File, byte[]> files) {

		static Snapshot take(File workspaceDir, List<Update> updates) throws Exception {
			Map<File, byte[]> files = new LinkedHashMap<>();
			for (Update update : updates) {
				if (update.index() != null) {
					File index = new File(update.index()).isAbsolute() ? new File(update.index())
						: new File(workspaceDir, update.index());
					if (index.isFile()) {
						files.put(index, Files.readAllBytes(index.toPath()));
					}
				}
			}
			try (Workspace workspace = new Workspace(workspaceDir)) {
				for (File bndrun : new ResolveCheck(workspace).bndruns()) {
					files.put(bndrun, Files.readAllBytes(bndrun.toPath()));
				}
			}
			return new Snapshot(files);
		}

		void restore() throws Exception {
			for (Map.Entry<File, byte[]> e : files.entrySet()) {
				Files.write(e.getKey()
					.toPath(), e.getValue());
			}
		}
	}
}
