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

import java.util.List;

import aQute.bnd.version.MavenVersion;

/**
 * Newer versions of a library in a repository index.
 *
 * @param library the library at the version the index holds
 * @param repository the repository whose index holds it
 * @param index the index file ({@code .mvn}) that has to change to update it, may be {@code null}
 * @param origin who owns {@code index}: only an index of the workspace itself is changed by an
 *            update; one contributed by a {@code -library} names that library as its source.
 *            {@code null} when there is no index
 * @param available all higher versions the repositories offer, ascending, without pre-releases
 * @param allowed the scope the version policy allows for this library
 * @param proposed the highest available version within {@code allowed}; {@code null} if there
 *            is none
 * @param latest the highest available version at all
 * @param usage whether the library is part of the application or only needed to build it; see
 *            {@link Usage}
 * @param shadowedBy when another index offers a higher version of the same library, which one
 *            ({@code 2.3.0 in Central}): bnd resolves to the highest version any index offers, so
 *            this entry is not used and no update is proposed for it; otherwise {@code null}
 */
public record Update(Library library, String repository, String index, IndexOrigin origin,
	List<MavenVersion> available, Scope allowed, MavenVersion proposed, MavenVersion latest, Usage usage,
	String shadowedBy) {

	/** Where a library is needed. */
	public enum Usage {
		/**
		 * in the application: in the {@code -runbundles}, {@code -runfw} or {@code -runpath} of
		 * an application bndrun — strict policy, an update can break consumers
		 */
		RUNTIME,
		/**
		 * only to build or test: in no application bndrun (build path, tests, code generators,
		 * the bnd toolchain); never reaches the application or its SBOM
		 */
		BUILD_TIME,
		/** not determined (no bndrun to tell from) */
		UNKNOWN
	}

	public Update {
		available = List.copyOf(available);
		if (index != null && origin == null) {
			origin = IndexOrigin.WORKSPACE;
		}
		if (usage == null) {
			usage = Usage.UNKNOWN;
		}
	}

	/** An update of unknown usage, not shadowed. */
	public Update(Library library, String repository, String index, IndexOrigin origin, List<MavenVersion> available,
		Scope allowed, MavenVersion proposed, MavenVersion latest) {
		this(library, repository, index, origin, available, allowed, proposed, latest, Usage.UNKNOWN, null);
	}

	/** An update whose index, if any, belongs to the workspace. */
	public Update(Library library, String repository, String index, List<MavenVersion> available, Scope allowed,
		MavenVersion proposed, MavenVersion latest) {
		this(library, repository, index, index != null ? IndexOrigin.WORKSPACE : null, available, allowed, proposed,
			latest);
	}

	/** {@code true} if another index offers a higher version, so this entry is not used. */
	public boolean isShadowed() {
		return shadowedBy != null;
	}

	/** {@code true} if the library is only needed to build or test, not in the application. */
	public boolean isBuildTime() {
		return usage == Usage.BUILD_TIME;
	}

	/** {@code true} if the index is one the update may change (the workspace's own). */
	public boolean isWritable() {
		return origin != null && origin.isWritable();
	}

	/** {@code true} if the policy allows an update. */
	public boolean isProposed() {
		return proposed != null;
	}

	/** The scope of the step to the latest version. */
	public Scope latestScope() {
		return Scope.of(library.mavenVersion(), latest);
	}
}
