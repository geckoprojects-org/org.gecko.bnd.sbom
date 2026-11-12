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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Tiny, self-contained SPDX license normalizer. bnd ships no runtime SPDX list, so the ids,
 * names and URLs that occur in practice are listed here.
 * <p>
 * Recognizes
 * <ul>
 * <li>SPDX ids ({@code epl-2.0} → {@code EPL-2.0})</li>
 * <li>common license names ({@code Eclipse Public License - v 2.0}, {@code The Apache Software
 * License, Version 2.0})</li>
 * <li>license URLs (opensource.org, apache.org, eclipse.org, gnu.org)</li>
 * <li>SPDX license expressions made of known ids ({@code (Apache-2.0 OR EPL-2.0)})</li>
 * </ul>
 * Deliberately conservative: an unrecognized value returns {@code null} → the caller keeps it
 * as free text instead of asserting a wrong SPDX id. Ambiguous names (LGPL without "only" or
 * "or later", "BSD license") are not mapped.
 */
public final class SpdxLicenses {

	private static final List<String>			OPENSOURCE_PREFIXES	= List.of("opensource.org/licenses/",
		"opensource.org/license/");

	/** lowercased id → canonical-cased SPDX id */
	private static final Map<String, String>	KNOWN				= new HashMap<>();
	/** lowercased exception id → canonical-cased SPDX exception id */
	private static final Map<String, String>	EXCEPTIONS			= new HashMap<>();
	/** normalized license name → SPDX id */
	private static final Map<String, String>	NAMES				= new HashMap<>();
	/** lowercased URL fragment → SPDX id or expression (checked in insertion order) */
	private static final Map<String, String>	URLS				= new LinkedHashMap<>();

	private static final Pattern				LICENSE_REF			= Pattern.compile("(?:DocumentRef-[A-Za-z0-9.-]+:)?LicenseRef-[A-Za-z0-9.-]+");
	private static final Pattern				TOKEN				= Pattern.compile("\\(|\\)|[^\\s()]+");

	static {
		for (String id : new String[] {
			"0BSD", "AGPL-3.0-only", "AGPL-3.0-or-later", "Apache-1.1", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause",
			"CC0-1.0", "CDDL-1.0", "CDDL-1.1", "CPL-1.0", "EPL-1.0", "EPL-2.0", "GPL-2.0", "GPL-2.0-only",
			"GPL-2.0-or-later", "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later", "ISC", "LGPL-2.1", "LGPL-2.1-only",
			"LGPL-2.1-or-later", "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later", "MIT", "MIT-0", "MPL-1.1",
			"MPL-2.0", "Unlicense", "UPL-1.0", "Zlib"
		}) {
			KNOWN.put(id.toLowerCase(Locale.ROOT), id);
		}
		for (String id : new String[] {
			"Classpath-exception-2.0", "LLVM-exception"
		}) {
			EXCEPTIONS.put(id.toLowerCase(Locale.ROOT), id);
		}

		NAMES.put("eclipse public license 2.0", "EPL-2.0");
		NAMES.put("eclipse public license 1.0", "EPL-1.0");
		NAMES.put("epl 2.0", "EPL-2.0");
		NAMES.put("epl 1.0", "EPL-1.0");
		NAMES.put("apache license 2.0", "Apache-2.0");
		NAMES.put("apache software license 2.0", "Apache-2.0");
		NAMES.put("apache 2.0", "Apache-2.0");
		NAMES.put("asl 2.0", "Apache-2.0");
		NAMES.put("mit license", "MIT");
		NAMES.put("mozilla public license 2.0", "MPL-2.0");
		// The Eclipse Distribution License 1.0 is the BSD 3-Clause license (Eclipse Foundation).
		NAMES.put("eclipse distribution license 1.0", "BSD-3-Clause");
		NAMES.put("edl 1.0", "BSD-3-Clause");
		NAMES.put("bsd 3 clause license", "BSD-3-Clause");
		NAMES.put("new bsd license", "BSD-3-Clause");
		NAMES.put("bsd 2 clause license", "BSD-2-Clause");
		NAMES.put("simplified bsd license", "BSD-2-Clause");
		NAMES.put("universal permissive license 1.0", "UPL-1.0");

		URLS.put("apache.org/licenses/license-2.0", "Apache-2.0");
		URLS.put("eclipse.org/legal/epl-v10", "EPL-1.0");
		URLS.put("eclipse.org/legal/epl-v20", "EPL-2.0");
		URLS.put("eclipse.org/legal/epl-2.0", "EPL-2.0");
		URLS.put("eclipse.org/org/documents/epl-2.0", "EPL-2.0");
		URLS.put("eclipse.org/org/documents/epl-v10", "EPL-1.0");
		URLS.put("eclipse.org/org/documents/edl-v10", "BSD-3-Clause");
		URLS.put("opensource.org/licenses/mit-license", "MIT");
		URLS.put("mozilla.org/mpl/2.0", "MPL-2.0");
		// GNU Classpath's license page: GPL 2 with the Classpath exception (Java EE / Jakarta)
		URLS.put("gnu.org/software/classpath/license", "GPL-2.0-only WITH Classpath-exception-2.0");
	}

	private SpdxLicenses() {}

	/**
	 * @param nameOrUrl a {@code Bundle-License} name or link, a POM license name or URL
	 * @return the canonical SPDX id, or {@code null} if not confidently recognized as a single
	 *         license (an expression yields {@code null} here, see {@link #toExpression})
	 */
	public static String toId(String nameOrUrl) {
		String result = toExpression(nameOrUrl);
		return result != null && KNOWN.containsValue(result) ? result : null;
	}

	/**
	 * @param nameOrUrl a license id, name, URL or SPDX expression
	 * @return a canonical SPDX id or SPDX license expression, or {@code null} if not confidently
	 *         recognized
	 */
	public static String toExpression(String nameOrUrl) {
		if (nameOrUrl == null) {
			return null;
		}
		String value = nameOrUrl.trim();
		if (value.isEmpty()) {
			return null;
		}
		String lower = value.toLowerCase(Locale.ROOT);

		String direct = KNOWN.get(lower);
		if (direct != null) {
			return direct;
		}

		for (String prefix : OPENSOURCE_PREFIXES) {
			int idx = lower.indexOf(prefix);
			if (idx >= 0) {
				String tail = value.substring(idx + prefix.length())
					.split("[/?#]", 2)[0];
				String mapped = KNOWN.get(stripExtension(tail).toLowerCase(Locale.ROOT));
				if (mapped != null) {
					return mapped;
				}
			}
		}
		for (Map.Entry<String, String> entry : URLS.entrySet()) {
			if (lower.contains(entry.getKey())) {
				return entry.getValue();
			}
		}

		String byName = NAMES.get(normalizeName(value));
		if (byName != null) {
			return byName;
		}
		return expression(value);
	}

	/**
	 * Lowercase, without punctuation, the article "the", the word "version" and a "v" before
	 * the version number: {@code The Apache Software License, Version 2.0} →
	 * {@code apache software license 2.0}.
	 */
	static String normalizeName(String name) {
		String n = name.toLowerCase(Locale.ROOT)
			.replaceAll("[,()\\-_/\"]", " ")
			.replaceAll("\\bthe\\b", " ")
			.replaceAll("\\bversion\\b", " ")
			.replaceAll("\\bv\\s*(?=\\d)", " ")
			.replaceAll("\\s+", " ")
			.trim();
		return n;
	}

	/**
	 * A valid SPDX expression of known ids: at least one operator, balanced parentheses, every
	 * operand a known license id or LicenseRef, every {@code WITH} followed by a known exception.
	 * Returned with canonical casing and spacing; {@code null} otherwise.
	 */
	private static String expression(String value) {
		List<String> tokens = new ArrayList<>();
		Matcher matcher = TOKEN.matcher(value);
		while (matcher.find()) {
			tokens.add(matcher.group());
		}
		int depth = 0;
		boolean operator = false;
		boolean expectOperand = true;
		boolean afterWith = false;
		List<String> canonical = new ArrayList<>();
		for (String token : tokens) {
			String upper = token.toUpperCase(Locale.ROOT);
			if (token.equals("(")) {
				if (!expectOperand) {
					return null;
				}
				depth++;
				canonical.add(token);
			} else if (token.equals(")")) {
				if (expectOperand || --depth < 0) {
					return null;
				}
				canonical.add(token);
			} else if (upper.equals("AND") || upper.equals("OR") || upper.equals("WITH")) {
				if (expectOperand) {
					return null;
				}
				operator = true;
				expectOperand = true;
				afterWith = upper.equals("WITH");
				canonical.add(upper);
			} else {
				if (!expectOperand) {
					return null;
				}
				String operand = afterWith ? EXCEPTIONS.get(token.toLowerCase(Locale.ROOT)) : license(token);
				if (operand == null) {
					return null;
				}
				canonical.add(operand);
				expectOperand = false;
				afterWith = false;
			}
		}
		if (!operator || expectOperand || depth != 0) {
			return null;
		}
		return String.join(" ", canonical)
			.replace("( ", "(")
			.replace(" )", ")");
	}

	private static String license(String token) {
		String known = KNOWN.get(token.toLowerCase(Locale.ROOT));
		if (known != null) {
			return known;
		}
		if (token.endsWith("+") && KNOWN.containsKey(token.substring(0, token.length() - 1)
			.toLowerCase(Locale.ROOT))) {
			return KNOWN.get(token.substring(0, token.length() - 1)
				.toLowerCase(Locale.ROOT)) + "+";
		}
		return LICENSE_REF.matcher(token)
			.matches() ? token : null;
	}

	private static String stripExtension(String tail) {
		int dot = tail.lastIndexOf('.');
		if (dot > 0) {
			String ext = tail.substring(dot + 1)
				.toLowerCase(Locale.ROOT);
			if (ext.equals("php") || ext.equals("html") || ext.equals("txt")) {
				return tail.substring(0, dot);
			}
		}
		return tail;
	}
}
