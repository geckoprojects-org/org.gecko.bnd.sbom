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
package org.gecko.bnd.update.maven;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.TreeSet;

import org.gecko.bnd.update.VersionSource;

import aQute.bnd.build.Workspace;
import aQute.bnd.repository.maven.provider.MavenBndRepository;
import aQute.bnd.version.MavenVersion;
import aQute.maven.api.Program;
import aQute.maven.api.Revision;

/**
 * The versions the Maven repositories of a bnd workspace offer for a library — what
 * {@code bnd mbr check} and the Bndtools repository view list as updates. Read from the
 * repositories' {@code maven-metadata.xml} through bnd, with the workspace's connection
 * settings; snapshots and pre-releases are left out.
 */
public final class MavenRepositoryVersions implements VersionSource {

	private final List<MavenBndRepository> repositories;

	public MavenRepositoryVersions(List<MavenBndRepository> repositories) {
		this.repositories = List.copyOf(repositories);
	}

	public static MavenRepositoryVersions of(Workspace workspace) {
		return new MavenRepositoryVersions(workspace.getPlugins(MavenBndRepository.class));
	}

	/**
	 * Asks the repositories whose index holds the library — as {@code bnd mbr} does; only when
	 * no index holds it (an embedded library) all repositories. Asking every repository for
	 * every library costs one metadata download per repository and library.
	 */
	@Override
	public List<MavenVersion> available(String groupId, String artifactId) throws Exception {
		Program program = Program.valueOf(groupId, artifactId);
		List<MavenBndRepository> holding = repositories.stream()
			.filter(r -> r.getArchives()
				.stream()
				.anyMatch(a -> a.revision.program.equals(program)))
			.toList();
		TreeSet<MavenVersion> versions = new TreeSet<>();
		for (MavenBndRepository repository : holding.isEmpty() ? repositories : holding) {
			for (Revision revision : repository.getRevisions(program)) {
				MavenVersion version = revision.version;
				if (!isPreRelease(version)) {
					versions.add(version);
				}
			}
		}
		return new ArrayList<>(versions);
	}

	/** -SNAPSHOT, -rc1, -beta12, -alpha, -M3: not proposed as a fix. */
	static boolean isPreRelease(MavenVersion version) {
		String text = version.toString()
			.toLowerCase(Locale.ROOT);
		return text.endsWith("-snapshot") || text.matches(".*[-.](alpha|beta|rc|cr|m|milestone|preview|pre)[-.]?\\d*([-.].*)?$");
	}
}
