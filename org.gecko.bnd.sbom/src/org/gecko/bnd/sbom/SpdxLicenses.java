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

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Tiny, self-contained SPDX license-id normalizer. bnd ships no runtime SPDX list — only
 * {@code @BundleLicense}-annotated marker classes in {@code biz.aQute.bnd.annotation}
 * ({@code @Retention(CLASS)}, not loadable at runtime). This transcribes that canonical
 * id ↔ URL set so a {@code Bundle-License} value can be recognized as a valid SPDX id.
 * <p>
 * Deliberately conservative: an unrecognized value returns {@code null} → the caller keeps
 * it as free-text {@code license.name} instead of asserting a wrong SPDX id.
 */
public final class SpdxLicenses {

	private static final String		OPENSOURCE_PREFIX	= "opensource.org/licenses/";

	/** lowercased id → canonical-cased SPDX id */
	private static final Map<String, String>	KNOWN		= new HashMap<>();
	/** lowercased URL fragment → SPDX id (non-opensource.org links) */
	private static final Map<String, String>	EXTRA_URLS	= new HashMap<>();

	static {
		for (String id : new String[] {
			"Apache-2.0", "MIT", "EPL-1.0", "EPL-2.0", "BSD-2-Clause", "BSD-3-Clause", "GPL-2.0", "GPL-2.0-only",
			"GPL-2.0-or-later", "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later", "LGPL-2.1", "LGPL-2.1-only",
			"LGPL-2.1-or-later", "MPL-2.0", "CDDL-1.0", "CPL-1.0"
		}) {
			KNOWN.put(id.toLowerCase(Locale.ROOT), id);
		}
		EXTRA_URLS.put("apache.org/licenses/license-2.0", "Apache-2.0");
		EXTRA_URLS.put("eclipse.org/legal/epl-v10", "EPL-1.0");
		EXTRA_URLS.put("eclipse.org/legal/epl-2.0", "EPL-2.0");
		EXTRA_URLS.put("eclipse.org/org/documents/epl-2.0", "EPL-2.0");
	}

	private SpdxLicenses() {}

	/**
	 * @param nameOrUrl a {@code Bundle-License} name or link
	 * @return the canonical SPDX id, or {@code null} if not confidently recognized
	 */
	public static String toId(String nameOrUrl) {
		if (nameOrUrl == null) {
			return null;
		}
		String value = nameOrUrl.trim();
		if (value.isEmpty()) {
			return null;
		}

		String direct = KNOWN.get(value.toLowerCase(Locale.ROOT));
		if (direct != null) {
			return direct;
		}

		String lower = value.toLowerCase(Locale.ROOT);
		int idx = lower.indexOf(OPENSOURCE_PREFIX);
		if (idx >= 0) {
			String tail = value.substring(idx + OPENSOURCE_PREFIX.length())
				.split("[/?#]", 2)[0];
			String mapped = KNOWN.get(tail.toLowerCase(Locale.ROOT));
			if (mapped != null) {
				return mapped;
			}
		}
		for (Map.Entry<String, String> entry : EXTRA_URLS.entrySet()) {
			if (lower.contains(entry.getKey())) {
				return entry.getValue();
			}
		}
		return null;
	}
}
