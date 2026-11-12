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
package org.gecko.bnd.sbom.model;

/**
 * A single license on a component — a validated SPDX id, a validated SPDX license expression
 * or a free-text name. A component may carry several (a header listing multiple). Format-neutral:
 * CycloneDX maps an id to {@code license.id}, an expression to {@code expression} and free text
 * to {@code license.name}; SPDX puts ids and expressions into the license expression and free
 * text into a {@code LicenseRef}.
 */
public final class SbomLicense {

	private final String	spdxId;
	private final String	expression;
	private final String	name;

	private SbomLicense(String spdxId, String expression, String name) {
		this.spdxId = spdxId;
		this.expression = expression;
		this.name = name;
	}

	/** A validated SPDX license id, e.g. {@code Apache-2.0}. */
	public static SbomLicense spdx(String id) {
		return new SbomLicense(id, null, null);
	}

	/** A validated SPDX license expression, e.g. {@code (Apache-2.0 OR EPL-2.0)}. */
	public static SbomLicense expression(String expression) {
		return new SbomLicense(null, expression, null);
	}

	/** A free-text / URL license that could not be resolved to an SPDX id or expression. */
	public static SbomLicense named(String name) {
		return new SbomLicense(null, null, name);
	}

	public boolean isSpdx() {
		return spdxId != null;
	}

	public boolean isExpression() {
		return expression != null;
	}

	/** Canonical SPDX id, or {@code null}. */
	public String spdxId() {
		return spdxId;
	}

	/** Canonical SPDX expression, or {@code null}. */
	public String expression() {
		return expression;
	}

	/** Free-text/URL license, or {@code null}. */
	public String name() {
		return name;
	}

	/**
	 * This license as an operand of a larger SPDX expression: the id, or the expression in
	 * parentheses unless it already is one parenthesized group; {@code null} for free text.
	 */
	public String asOperand() {
		if (spdxId != null) {
			return spdxId;
		}
		if (expression != null) {
			return isParenthesized(expression) ? expression : "(" + expression + ")";
		}
		return null;
	}

	private static boolean isParenthesized(String value) {
		if (!value.startsWith("(") || !value.endsWith(")")) {
			return false;
		}
		int depth = 0;
		for (int i = 0; i < value.length(); i++) {
			char c = value.charAt(i);
			if (c == '(') {
				depth++;
			} else if (c == ')' && --depth == 0 && i < value.length() - 1) {
				return false;
			}
		}
		return true;
	}
}
