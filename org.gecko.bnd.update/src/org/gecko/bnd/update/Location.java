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

/**
 * Where a library sits in the application, as the SBOM records it — and therefore what has to
 * change to update it.
 *
 * @param layer {@code runbundle}, {@code runfw}, {@code runpath} for a component of the run;
 *            {@code embedded} for a library inside a bundle
 * @param bundle for an embedded library: the bundle that contains it; otherwise {@code null}
 * @param source for an embedded library: where it was found (pom.properties path, Bundle-ClassPath
 *            jar, or the {@code -buildpath} entry it was inlined from); otherwise {@code null}
 * @param repository the repository the component was taken from, may be {@code null}
 */
public record Location(String layer, String bundle, String source, String repository) {

	public static final String EMBEDDED = "embedded";

	public boolean isEmbedded() {
		return EMBEDDED.equals(layer);
	}
}
