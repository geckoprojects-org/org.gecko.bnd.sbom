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
 * The creator of the SBOM or of a component (BSI TR-03183-2 §5.2.1/§5.2.2). The TR asks for an
 * email address, or else a URL; the name ({@code Bundle-Vendor}) is written alongside, but does
 * not identify the creator on its own.
 *
 * @param name may be {@code null}
 * @param email may be {@code null}
 * @param url may be {@code null}
 */
public record SbomCreator(String name, String email, String url) {

	/**
	 * @return the creator, or {@code null} when none of the values is given
	 */
	public static SbomCreator of(String name, String email, String url) {
		if (isBlank(name) && isBlank(email) && isBlank(url)) {
			return null;
		}
		return new SbomCreator(blankToNull(name), blankToNull(email), blankToNull(url));
	}

	/** {@code true} when the creator can be reached as the TR asks: by email address or URL. */
	public boolean isIdentified() {
		return email != null || url != null;
	}

	private static boolean isBlank(String value) {
		return value == null || value.isBlank();
	}

	private static String blankToNull(String value) {
		return isBlank(value) ? null : value.trim();
	}
}
