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
 * The versions of a library that are available to the build. In a bnd workspace: the versions
 * its Maven repositories offer ({@link org.gecko.bnd.update.maven.MavenRepositoryVersions}).
 */
@FunctionalInterface
public interface VersionSource {

	/**
	 * @return the available versions, in any order; empty when the library is unknown
	 */
	List<MavenVersion> available(String groupId, String artifactId) throws Exception;
}
