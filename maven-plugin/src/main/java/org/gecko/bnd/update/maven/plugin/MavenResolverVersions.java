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

import java.util.ArrayList;
import java.util.List;

import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.resolution.VersionRangeRequest;
import org.eclipse.aether.resolution.VersionRangeResult;
import org.eclipse.aether.version.Version;
import org.gecko.bnd.update.VersionSource;
import org.gecko.bnd.update.maven.MavenRepositoryVersions;

import aQute.bnd.version.MavenVersion;

/**
 * The versions of a library in the project's Maven repositories, through Maven's own resolver —
 * with the project's repositories, mirrors, proxies and credentials. Pre-releases are left out.
 */
final class MavenResolverVersions implements VersionSource {

	private final RepositorySystem			system;
	private final RepositorySystemSession	session;
	private final List<RemoteRepository>	repositories;

	MavenResolverVersions(RepositorySystem system, RepositorySystemSession session,
		List<RemoteRepository> repositories) {
		this.system = system;
		this.session = session;
		this.repositories = repositories;
	}

	@Override
	public List<MavenVersion> available(String groupId, String artifactId) throws Exception {
		VersionRangeRequest request = new VersionRangeRequest(new DefaultArtifact(groupId, artifactId, "jar", "[0,)"),
			repositories, null);
		VersionRangeResult result = system.resolveVersionRange(session, request);
		List<MavenVersion> versions = new ArrayList<>();
		for (Version version : result.getVersions()) {
			MavenVersion mavenVersion;
			try {
				mavenVersion = new MavenVersion(version.toString());
			} catch (IllegalArgumentException e) {
				continue; // a version bnd cannot compare is not proposed
			}
			if (!MavenRepositoryVersions.isPreRelease(mavenVersion)) {
				versions.add(mavenVersion);
			}
		}
		return versions;
	}
}
