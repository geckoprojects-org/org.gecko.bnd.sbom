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

import java.net.URI;
import java.util.Collection;

import org.osgi.resource.Resource;

import aQute.bnd.osgi.resource.ResourceUtils;
import aQute.bnd.osgi.resource.ResourceUtils.ContentCapability;
import aQute.bnd.osgi.resource.ResourceUtils.IdentityCapability;
import aQute.bnd.version.Version;

/**
 * The bundle behind a library of a Maven index: the repositories index each archive as a resource,
 * whose content URL holds the Maven path ({@code …/group/path/artifact/version/…}).
 */
final class Bundles {

	private Bundles() {}

	/**
	 * A bundle as the resolver names it.
	 *
	 * @param resource the indexed resource
	 */
	record Bundle(String bsn, Version version, Resource resource) {

		/** {@code bsn version}, as the resolver reports the requiring bundle */
		String identity() {
			return bsn + " " + version;
		}
	}

	/** The bundle of a library among the resources, or {@code null}. */
	static Bundle of(Library library, Collection<Resource> resources) {
		String path = "/" + library.groupId()
			.replace('.', '/') + "/" + library.artifactId() + "/" + library.version() + "/";
		for (Resource resource : resources) {
			if (matches(resource, path)) {
				IdentityCapability identity = ResourceUtils.getIdentityCapability(resource);
				if (identity != null && identity.osgi_identity() != null && identity.version() != null) {
					return new Bundle(identity.osgi_identity(), identity.version(), resource);
				}
			}
		}
		return null;
	}

	private static boolean matches(Resource resource, String path) {
		for (ContentCapability content : ResourceUtils.getContentCapabilities(resource)) {
			URI url = content.url();
			if (url != null && String.valueOf(url.getPath())
				.contains(path)) {
				return true;
			}
		}
		return false;
	}
}
