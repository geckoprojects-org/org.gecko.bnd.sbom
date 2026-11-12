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

import java.nio.charset.StandardCharsets;

/**
 * Minimal Package-URL (PURL) builder for the {@code maven} type. bnd has no PURL library, so
 * we build the canonical string ourselves and percent-encode per RFC 3986 (unreserved set
 * {@code A-Z a-z 0-9 - . _ ~} passes through). Shape:
 * {@code pkg:maven/{groupId}/{artifactId}@{version}[?classifier=..&type=..]}.
 *
 * @see <a href="https://github.com/package-url/purl-spec">purl-spec</a>
 */
public final class Purl {

	private static final String DEFAULT_MAVEN_TYPE = "jar";

	private Purl() {}

	/**
	 * @return a {@code pkg:maven/...} PURL, or {@code null} if group, artifact or version is
	 *         missing (an incomplete coordinate must not become a fake PURL — Q3).
	 */
	public static String maven(String groupId, String artifactId, String version, String classifier,
		String extension) {
		if (isBlank(groupId) || isBlank(artifactId) || isBlank(version)) {
			return null;
		}

		StringBuilder purl = new StringBuilder("pkg:maven/").append(encode(groupId))
			.append('/')
			.append(encode(artifactId))
			.append('@')
			.append(encode(version));

		// Qualifiers must be sorted by key in canonical form: classifier before type.
		String qualifiers = qualifiers(classifier, extension);
		if (qualifiers != null) {
			purl.append('?')
				.append(qualifiers);
		}
		return purl.toString();
	}

	private static String qualifiers(String classifier, String extension) {
		StringBuilder sb = new StringBuilder();
		if (!isBlank(classifier)) {
			sb.append("classifier=")
				.append(encode(classifier));
		}
		// The maven type qualifier defaults to "jar"; only emit a deviating extension.
		if (!isBlank(extension) && !DEFAULT_MAVEN_TYPE.equalsIgnoreCase(extension.trim())) {
			if (sb.length() > 0) {
				sb.append('&');
			}
			sb.append("type=")
				.append(encode(extension));
		}
		return sb.length() == 0 ? null : sb.toString();
	}

	private static String encode(String value) {
		StringBuilder out = new StringBuilder();
		for (byte b : value.trim()
			.getBytes(StandardCharsets.UTF_8)) {
			int c = b & 0xFF;
			if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.'
				|| c == '_' || c == '~') {
				out.append((char) c);
			} else {
				out.append('%')
					.append(Character.toUpperCase(Character.forDigit((c >> 4) & 0xF, 16)))
					.append(Character.toUpperCase(Character.forDigit(c & 0xF, 16)));
			}
		}
		return out.toString();
	}

	private static boolean isBlank(String s) {
		return s == null || s.trim()
			.isEmpty();
	}
}
