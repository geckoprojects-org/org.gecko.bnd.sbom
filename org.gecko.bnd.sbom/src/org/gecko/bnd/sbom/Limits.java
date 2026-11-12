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
package org.gecko.bnd.sbom;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * Bounds for what the exporter reads from artifacts it does not control (CWE-400, CWE-409),
 * and the clean-up of URLs before they are published in an SBOM (CWE-200).
 * <p>
 * Bundles, the jars embedded in them, their manifests, POMs and license files come from
 * repositories. A crafted entry — a zip bomb as embedded jar, a gigabyte LICENSE file — must not
 * exhaust the build's memory. Everything read into memory is capped; what is larger is not
 * analysed, and the caller reports that.
 */
public final class Limits {

	/** an embedded jar that is analysed in memory (decompressed bytes) */
	public static final int	EMBEDDED_JAR	= 64 * 1024 * 1024;
	/** a POM, pom.properties or manifest-like metadata file */
	public static final int	METADATA		= 1024 * 1024;
	/** the part of a license text or about.html that is looked at */
	public static final int	LICENSE_TEXT	= 256 * 1024;

	private Limits() {}

	/**
	 * Reads at most {@code max} bytes.
	 *
	 * @return the bytes, or {@code null} when the stream holds more than {@code max} bytes
	 */
	public static byte[] read(InputStream in, int max) throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		byte[] buffer = new byte[8192];
		long total = 0;
		int n;
		while ((n = in.read(buffer)) > 0) {
			total += n;
			if (total > max) {
				return null;
			}
			out.write(buffer, 0, n);
		}
		return out.toByteArray();
	}

	/**
	 * Reads the first {@code max} bytes as UTF-8 text and ignores the rest — enough to
	 * recognize a license, never more than the cap in memory.
	 */
	public static String head(InputStream in, int max) throws IOException {
		byte[] bytes = in.readNBytes(max);
		return new String(bytes, StandardCharsets.UTF_8);
	}

	/**
	 * A URL as it may appear in a published SBOM: without user info (a {@code user:token@}
	 * in a repository URL), query and fragment, which can carry credentials as well. Returns
	 * {@code null} for anything that is not an absolute http(s) URL.
	 */
	public static String publishableUrl(String url) {
		if (url == null || url.isBlank()) {
			return null;
		}
		try {
			URI uri = new URI(url.trim());
			String scheme = uri.getScheme();
			if (scheme == null || !(scheme.equalsIgnoreCase("https") || scheme.equalsIgnoreCase("http"))
				|| uri.getHost() == null) {
				return null;
			}
			return new URI(scheme.toLowerCase(Locale.ROOT), null, uri.getHost(), uri.getPort(), uri.getPath(),
				null, null).toString();
		} catch (Exception e) {
			return null;
		}
	}
}
