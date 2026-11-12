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

	public UpdateFinder(List<MavenBndRepository> repositories, VersionSource versions, VersionPolicy policy) {
		this.repositories = List.copyOf(repositories);
		this.versions = versions;
		this.policy = policy;
	}

	public static UpdateFinder forWorkspace(Workspace workspace) {
		List<MavenBndRepository> repositories = workspace.getPlugins(MavenBndRepository.class);
		return new UpdateFinder(repositories, new MavenRepositoryVersions(repositories), VersionPolicy.from(workspace));
	}

	public UpdateFinder withPolicy(VersionPolicy policy) {
		return new UpdateFinder(repositories, versions, policy);
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
				updates.add(new Update(library, repository.getName(), index != null ? index.getPath() : null, higher,
					allowed, proposed, higher.get(higher.size() - 1)));
			}
		}
		updates.sort(Comparator.comparing((Update u) -> u.library()
			.ga())
			.thenComparing(u -> u.library()
				.mavenVersion()));
		return updates;
	}
}
