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
 * A single license on a component — either a validated SPDX id or a free-text name. A
 * component may carry several (dual-licensing, or a header listing multiple). Format-neutral:
 * CycloneDX maps an SPDX id to {@code license.id} and free text to {@code license.name}; SPDX
 * maps an id straight into the license expression and free text to a {@code LicenseRef}.
 */
public final class SbomLicense {

	private final String	spdxId;
	private final String	name;

	private SbomLicense(String spdxId, String name) {
		this.spdxId = spdxId;
		this.name = name;
	}

	/** A validated SPDX license id, e.g. {@code Apache-2.0}. */
	public static SbomLicense spdx(String id) {
		return new SbomLicense(id, null);
	}

	/** A free-text / URL license that could not be resolved to an SPDX id. */
	public static SbomLicense named(String name) {
		return new SbomLicense(null, name);
	}

	public boolean isSpdx() {
		return spdxId != null;
	}

	/** Canonical SPDX id, or {@code null}. */
	public String spdxId() {
		return spdxId;
	}

	/** Free-text/URL license, or {@code null}. */
	public String name() {
		return name;
	}
}
