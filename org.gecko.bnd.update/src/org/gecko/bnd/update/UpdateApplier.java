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

import aQute.bnd.build.Workspace;
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
 * reported as {@link AppliedUpdate.Status#NOT_IN_INDEX}.
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
			} else if (!indexFile(update).isFile() || update.index()
				.endsWith(".xml")) {
				results.add(new AppliedUpdate(update, AppliedUpdate.Status.NOT_IN_INDEX,
					"index " + update.index() + " is not a text index (.mvn); pom indexes are not changed"));
			} else {
				applicable.add(update);
			}
		}
		if (applicable.isEmpty()) {
			return new ApplyReport(mode, results, resolveAll(), null);
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
				} else {
					results.add(edited);
				}
			}
		}
		// the last successful build is the one of the final state: every later update that
		// failed was reverted
		return new ApplyReport(mode, results, resolveAll(), lastSuccessfulBuild);
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
		ResolveReport report = resolveAll();
		if (!report.allResolve()) {
			return report.results()
				.stream()
				.filter(r -> !r.resolves())
				.map(r -> r.bndrun() + " does not resolve"
					+ (r.unresolved()
						.isEmpty() ? (r.message() != null ? ": " + r.message() : "")
							: ": " + String.join("; ", r.unresolved())))
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
