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
 * @param available all higher versions the repositories offer, ascending, without pre-releases
 * @param allowed the scope the version policy allows for this library
 * @param proposed the highest available version within {@code allowed}; {@code null} if there
 *            is none
 * @param latest the highest available version at all
 */
public record Update(Library library, String repository, String index, List<MavenVersion> available, Scope allowed,
	MavenVersion proposed, MavenVersion latest) {

	public Update {
		available = List.copyOf(available);
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
