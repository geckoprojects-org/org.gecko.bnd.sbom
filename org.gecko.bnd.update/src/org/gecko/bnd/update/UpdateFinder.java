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
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.gecko.bnd.update.maven.MavenRepositoryVersions;
import org.osgi.resource.Resource;

import aQute.bnd.build.Workspace;
import aQute.bnd.repository.maven.provider.MavenBndRepository;
import aQute.bnd.version.MavenVersion;
import aQute.maven.api.Archive;

/**
 * Function 1: finds newer versions of the libraries in a workspace's Maven repository indexes
 * ({@code .mvn} files) — independent of any vulnerability report. The same information as
 * "Update Revisions" in the Bndtools repository view and {@code bnd mbr check}, with the
 * version policy applied: the proposal is the highest version within the allowed scope.
 * <p>
 * It only reads; applying an update (all or selected ones) and checking the result is a
 * separate step.
 */
public final class UpdateFinder {

	private final List<MavenBndRepository>	repositories;
	private final VersionSource				versions;
	private final VersionPolicy				policy;
	private final File						base;
	private final File						cache;
	private final RuntimeArtifacts			runtime;
	private final Toolchain					toolchain;

	/**
	 * @param base index paths are reported relative to this directory (the workspace); may be
	 *            {@code null} for absolute paths
	 */
	public UpdateFinder(List<MavenBndRepository> repositories, VersionSource versions, VersionPolicy policy,
		File base) {
		this(repositories, versions, policy, base, null);
	}

	/**
	 * @param base index paths are reported relative to this directory (the workspace); may be
	 *            {@code null} for absolute paths
	 * @param cache the workspace's bnd cache ({@code cnf/cache}): an index in it was expanded
	 *            from a {@code -library} and is read-only; may be {@code null}
	 */
	public UpdateFinder(List<MavenBndRepository> repositories, VersionSource versions, VersionPolicy policy,
		File base, File cache) {
		this(repositories, versions, policy, base, cache, null, null);
	}

	/**
	 * @param runtime what the application bndruns contain, to tell runtime from build-time
	 *            libraries; {@code null}: not classified
	 * @param toolchain the bnd version of the build, reported as a build-time update;
	 *            {@code null}: none
	 */
	UpdateFinder(List<MavenBndRepository> repositories, VersionSource versions, VersionPolicy policy, File base,
		File cache, RuntimeArtifacts runtime, Toolchain toolchain) {
		this.repositories = List.copyOf(repositories);
		this.versions = versions;
		this.policy = policy;
		this.base = base;
		this.cache = cache;
		this.runtime = runtime;
		this.toolchain = toolchain;
	}

	public static UpdateFinder forWorkspace(Workspace workspace) throws Exception {
		List<MavenBndRepository> repositories = workspace.getPlugins(MavenBndRepository.class);
		return new UpdateFinder(repositories, new MavenRepositoryVersions(repositories), VersionPolicy.from(workspace),
			workspace.getBase(), cacheOf(workspace), RuntimeArtifacts.of(workspace),
			Toolchain.detect(workspace.getBase()));
	}

	/** Directory of the bnd cache in {@code cnf}, parent of the per-bnd-version caches. */
	static final String CACHE = "cache";

	/** {@code cnf/cache}, the parent of the per-bnd-version caches. */
	static File cacheOf(Workspace workspace) {
		return new File(workspace.getBuildDir(), CACHE);
	}

	public UpdateFinder withPolicy(VersionPolicy policy) {
		return new UpdateFinder(repositories, versions, policy, base, cache, runtime, toolchain);
	}

	private IndexOrigin origin(File index) {
		return index == null ? null : IndexOrigin.of(index, base, cache);
	}

	/** The index file as reported: relative to the workspace when possible. */
	private String path(File index) {
		if (index == null) {
			return null;
		}
		Path path = index.toPath()
			.toAbsolutePath()
			.normalize();
		if (base != null) {
			Path root = base.toPath()
				.toAbsolutePath()
				.normalize();
			if (path.startsWith(root)) {
				return root.relativize(path)
					.toString();
			}
		}
		return path.toString();
	}

	/**
	 * The fixes of a vulnerability check as updates: for each proposal with a fix within the
	 * policy, the library's lines in the indexes that hold it. A library that no index holds
	 * (embedded in a workspace bundle) becomes an update without index.
	 */
	public List<Update> forProposals(List<Proposal> proposals) throws Exception {
		List<Update> updates = new ArrayList<>();
		for (Proposal proposal : proposals) {
			if (proposal.proposed() == null) {
				continue;
			}
			Library library = proposal.library();
			boolean found = false;
			for (MavenBndRepository repository : repositories) {
				boolean holds = repository.getArchives()
					.stream()
					.anyMatch(a -> a.revision.group.equals(library.groupId())
						&& a.revision.artifact.equals(library.artifactId()) && a.revision.version.toString()
							.equals(library.version()));
				if (holds) {
					File index = repository.getIndexFile();
					updates.add(new Update(library, repository.getName(), path(index), origin(index),
						List.of(proposal.proposed()), proposal.allowed(), proposal.proposed(), proposal.proposed()));
					found = true;
				}
			}
			if (!found) {
				updates.add(new Update(library, null, null, null, List.of(proposal.proposed()), proposal.allowed(),
					proposal.proposed(), proposal.proposed()));
			}
		}
		return updates;
	}

	/**
	 * Every library of every index that has a higher version available, sorted by coordinates —
	 * plus the bnd toolchain, if a newer bnd exists.
	 * <p>
	 * An entry for which another index offers a higher version of the same library is
	 * {@linkplain Update#shadowedBy() shadowed}: bnd resolves to the highest version any index
	 * offers, so updating this entry changes nothing; no update is proposed for it. Each library
	 * is classified as runtime or build-time ({@link Update.Usage}), and the policy applies
	 * accordingly ({@code buildtime} in {@code -update-policy}).
	 */
	public List<Update> find() throws Exception {
		record Entry(MavenBndRepository repository, File index, Library library) {}
		List<Entry> entries = new ArrayList<>();
		// an index may list a library more than once (other classifier or extension); one entry
		// per library, version and repository
		Set<String> seen = new HashSet<>();
		for (MavenBndRepository repository : repositories) {
			File index = repository.getIndexFile();
			for (Archive archive : new TreeSet<>(repository.getArchives())) {
				Library library = new Library(archive.revision.group, archive.revision.artifact,
					archive.revision.version.toString());
				if (seen.add(library + "@" + repository.getName())) {
					entries.add(new Entry(repository, index, library));
				}
			}
		}
		Map<String, String> shadows = shadows(entries.stream()
			.map(e -> new Indexed(e.library(), e.repository()
				.getName()))
			.toList());
		List<Resource> resources = new ArrayList<>();
		if (runtime != null) {
			for (MavenBndRepository repository : repositories) {
				resources.addAll(repository.getResources());
			}
		}

		List<Update> updates = new ArrayList<>();
		for (Entry entry : entries) {
			Library library = entry.library();
			MavenVersion installed = library.mavenVersion();
			List<MavenVersion> higher = higher(library);
			if (higher.isEmpty()) {
				continue;
			}
			Update.Usage usage = usage(library, resources);
			Scope allowed = policy.scopeFor(library.groupId(), library.artifactId(), usage);
			String shadowedBy = shadows.get(new Indexed(library, entry.repository()
				.getName()).key());
			MavenVersion proposed = shadowedBy != null ? null : proposed(installed, higher, allowed);
			updates.add(new Update(library, entry.repository()
				.getName(), path(entry.index()), origin(entry.index()), higher, allowed, proposed,
				higher.get(higher.size() - 1), usage, shadowedBy));
		}
		if (toolchain != null) {
			Library library = toolchain.library();
			List<MavenVersion> higher = higher(library);
			if (!higher.isEmpty()) {
				Scope allowed = policy.scopeFor(library.groupId(), library.artifactId(), Update.Usage.BUILD_TIME);
				updates.add(new Update(library, "bnd toolchain", toolchain.source()
					.split(" ")[0], new IndexOrigin(IndexOrigin.Kind.TOOLCHAIN, toolchain.source()), higher, allowed,
					proposed(library.mavenVersion(), higher, allowed), higher.get(higher.size() - 1),
					Update.Usage.BUILD_TIME, null));
			}
		}
		updates.sort(Comparator.comparing((Update u) -> u.library()
			.ga())
			.thenComparing(u -> u.library()
				.mavenVersion()));
		return updates;
	}

	/** only versions that continue the installed one: same variant, same scheme */
	private List<MavenVersion> higher(Library library) throws Exception {
		MavenVersion installed = library.mavenVersion();
		return versions.available(library.groupId(), library.artifactId())
			.stream()
			.filter(v -> v.compareTo(installed) > 0 && Scope.successor(installed, v))
			.sorted()
			.toList();
	}

	private static MavenVersion proposed(MavenVersion installed, List<MavenVersion> higher, Scope allowed) {
		return higher.stream()
			.filter(v -> allowed.allows(installed, v))
			.max(Comparator.naturalOrder())
			.orElse(null);
	}

	private Update.Usage usage(Library library, List<Resource> resources) {
		if (runtime == null) {
			return Update.Usage.UNKNOWN;
		}
		Bundles.Bundle bundle = Bundles.of(library, resources);
		return bundle != null && runtime.contains(bundle.bsn(), bundle.version()) ? Update.Usage.RUNTIME
			: Update.Usage.BUILD_TIME;
	}

	/** A library at a version in the index of a repository. */
	record Indexed(Library library, String repository) {
		String key() {
			return library + "@" + repository;
		}
	}

	/**
	 * The shadowed entries: for each, the highest version of the same library (same variant and
	 * scheme) that another repository offers, if it is higher — as {@code 2.3.0 in Central},
	 * keyed by {@link Indexed#key()}.
	 */
	static Map<String, String> shadows(List<Indexed> entries) {
		Map<String, List<Indexed>> byGa = new LinkedHashMap<>();
		for (Indexed entry : entries) {
			byGa.computeIfAbsent(entry.library()
				.ga(), k -> new ArrayList<>())
				.add(entry);
		}
		Map<String, String> shadows = new LinkedHashMap<>();
		for (List<Indexed> group : byGa.values()) {
			for (Indexed entry : group) {
				MavenVersion version = entry.library()
					.mavenVersion();
				group.stream()
					.filter(o -> !o.repository()
						.equals(entry.repository()))
					.filter(o -> o.library()
						.mavenVersion()
						.compareTo(version) > 0
						&& Scope.successor(version, o.library()
							.mavenVersion()))
					.max(Comparator.comparing(o -> o.library()
						.mavenVersion()))
					.ifPresent(o -> shadows.put(entry.key(), o.library()
						.version() + " in " + o.repository()));
			}
		}
		return shadows;
	}
}
