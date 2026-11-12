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
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import org.gecko.bnd.update.maven.MavenRepositoryVersions;

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

	/**
	 * @param base index paths are reported relative to this directory (the workspace); may be
	 *            {@code null} for absolute paths
	 */
	public UpdateFinder(List<MavenBndRepository> repositories, VersionSource versions, VersionPolicy policy,
		File base) {
		this.repositories = List.copyOf(repositories);
		this.versions = versions;
		this.policy = policy;
		this.base = base;
	}

	public static UpdateFinder forWorkspace(Workspace workspace) {
		List<MavenBndRepository> repositories = workspace.getPlugins(MavenBndRepository.class);
		return new UpdateFinder(repositories, new MavenRepositoryVersions(repositories), VersionPolicy.from(workspace),
			workspace.getBase());
	}

	public UpdateFinder withPolicy(VersionPolicy policy) {
		return new UpdateFinder(repositories, versions, policy, base);
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
					updates.add(new Update(library, repository.getName(), path(index), List.of(proposal.proposed()),
						proposal.allowed(), proposal.proposed(), proposal.proposed()));
					found = true;
				}
			}
			if (!found) {
				updates.add(new Update(library, null, null, List.of(proposal.proposed()), proposal.allowed(),
					proposal.proposed(), proposal.proposed()));
			}
		}
		return updates;
	}

	/** Every library of every index that has a higher version available, sorted by coordinates. */
	public List<Update> find() throws Exception {
		List<Update> updates = new ArrayList<>();
		// an index may list a library more than once (other classifier or extension); one entry
		// per library, version and repository
		Set<String> seen = new HashSet<>();
		for (MavenBndRepository repository : repositories) {
			File index = repository.getIndexFile();
			for (Archive archive : new TreeSet<>(repository.getArchives())) {
				Library library = new Library(archive.revision.group, archive.revision.artifact,
					archive.revision.version.toString());
				if (!seen.add(library + "@" + repository.getName())) {
					continue;
				}
				MavenVersion installed = archive.revision.version;
				List<MavenVersion> higher = versions.available(library.groupId(), library.artifactId())
					.stream()
					.filter(v -> v.compareTo(installed) > 0)
					.sorted()
					.toList();
				if (higher.isEmpty()) {
					continue;
				}
				Scope allowed = policy.scopeFor(library.groupId(), library.artifactId());
				MavenVersion proposed = higher.stream()
					.filter(v -> allowed.allows(installed, v))
					.max(Comparator.naturalOrder())
					.orElse(null);
				updates.add(new Update(library, repository.getName(), path(index), higher, allowed, proposed,
					higher.get(higher.size() - 1)));
			}
		}
		updates.sort(Comparator.comparing((Update u) -> u.library()
			.ga())
			.thenComparing(u -> u.library()
				.mavenVersion()));
		return updates;
	}
}
