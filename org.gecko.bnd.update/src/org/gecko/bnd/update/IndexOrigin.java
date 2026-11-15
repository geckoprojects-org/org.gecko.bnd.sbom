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
import java.util.Locale;

/**
 * Who owns a repository index, and therefore whether an update may change it.
 * <p>
 * Only the workspace's own indexes ({@code cnf/central.mvn}, …) are written. An index that a
 * bnd {@code -library} brings along is the content of a released library, expanded into the
 * bnd cache ({@code cnf/cache/<bnd version>/expanded/urn%resource%<bsn>-<version>/…}): a change
 * there is not part of the workspace, invisible to {@code git diff}, and overwritten on the next
 * expansion. Such an index is reported, but to update the library in it, its source has to be
 * updated — here, the library.
 *
 * @param kind see {@link Kind}
 * @param source for {@link Kind#LIBRARY}: the library, as {@code bsn version} (or the expanded
 *            directory's name when it is not a repository library); for {@link Kind#EXTERNAL}:
 *            the directory the index is in; for {@link Kind#TOOLCHAIN}: where the version is set
 *            ({@code gradle.properties bnd_version}); {@code null} for {@link Kind#WORKSPACE}
 */
public record IndexOrigin(Kind kind, String source) {

	public enum Kind {
		/** an index of the workspace itself: written by an update */
		WORKSPACE,
		/** an index contributed by a bnd {@code -library}, expanded in the bnd cache: read-only */
		LIBRARY,
		/** an index outside the workspace, or elsewhere in the bnd cache: read-only */
		EXTERNAL,
		/**
		 * not an index: the bnd version of the workspace's build ({@code gradle.properties},
		 * {@code settings.gradle}); reported, not changed by an update
		 */
		TOOLCHAIN
	}

	public static final IndexOrigin	WORKSPACE		= new IndexOrigin(Kind.WORKSPACE, null);

	/** Directory of the bnd cache that holds expanded resources. */
	static final String				EXPANDED		= "expanded";
	/** {@code urn:resource:} as {@code IO.toSafeFileName} writes it, on Unix and Windows */
	static final String				URN_RESOURCE	= "urn%resource%";

	/** {@code true} if an update may change the index. */
	public boolean isWritable() {
		return kind == Kind.WORKSPACE;
	}

	/** For reports: {@code workspace}, {@code library <bsn> <version>}, {@code external <dir>}. */
	@Override
	public String toString() {
		return kind.name()
			.toLowerCase(Locale.ROOT) + (source != null ? " " + source : "");
	}

	/**
	 * Classifies an index file.
	 *
	 * @param index the index file
	 * @param workspace the workspace directory; may be {@code null} (everything is then
	 *            {@link Kind#WORKSPACE}, as without a workspace there is nothing to tell apart)
	 * @param cache the workspace's bnd cache ({@code cnf/cache}); may be {@code null}
	 */
	public static IndexOrigin of(File index, File workspace, File cache) {
		if (workspace == null) {
			return WORKSPACE;
		}
		Path path = normalize(index);
		if (cache != null) {
			Path cacheRoot = normalize(cache);
			if (path.startsWith(cacheRoot)) {
				return inCache(cacheRoot.relativize(path), path);
			}
		}
		if (path.startsWith(normalize(workspace))) {
			return WORKSPACE;
		}
		Path parent = path.getParent();
		return new IndexOrigin(Kind.EXTERNAL, String.valueOf(parent != null ? parent : path));
	}

	/**
	 * An index in the cache: {@code <bnd version>/expanded/<resource>/…}, where a repository
	 * library's resource is {@code urn%resource%<bsn>-<version>}.
	 */
	private static IndexOrigin inCache(Path relative, Path path) {
		for (int i = 0; i + 1 < relative.getNameCount() - 1; i++) {
			if (EXPANDED.equals(relative.getName(i)
				.toString())) {
				return new IndexOrigin(Kind.LIBRARY, library(relative.getName(i + 1)
					.toString()));
			}
		}
		Path parent = path.getParent();
		return new IndexOrigin(Kind.EXTERNAL, String.valueOf(parent != null ? parent : path));
	}

	/** {@code urn%resource%org.example.lib-1.1.0} → {@code org.example.lib 1.1.0} */
	static String library(String resource) {
		if (!resource.startsWith(URN_RESOURCE)) {
			return resource;
		}
		String id = resource.substring(URN_RESOURCE.length());
		// bnd writes <bsn>-<version without qualifier>; a bsn may itself contain '-', a version
		// does not
		int dash = id.lastIndexOf('-');
		return dash > 0 ? id.substring(0, dash) + " " + id.substring(dash + 1) : id;
	}

	private static Path normalize(File file) {
		return file.toPath()
			.toAbsolutePath()
			.normalize();
	}
}
