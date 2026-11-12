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

import java.util.Optional;

/**
 * Cumulative maturity levels (each level is a superset of the previous). Named neutrally,
 * not after a regulation — see requirements/anforderungen-sbom-schichten.md §7. The output
 * format and the {@code includeOSGIMetadata} flag are orthogonal to these levels.
 */
public enum SbomLevel {

	/** NTIA minimum: broadly applicable, valid baseline (default). */
	SIMPLE("simple"),
	/** CRA / BSI TR-03183-2: + hash, license, filename, completeness indicator. */
	MEDIUM("medium"),
	/** FDA + maximum OSGi evidence: + supplier/third-party, linking. */
	FULL("full");

	private final String id;

	SbomLevel(String id) {
		this.id = id;
	}

	public String id() {
		return id;
	}

	/** {@code true} if this level includes {@code other} (cumulative). */
	public boolean includes(SbomLevel other) {
		return ordinal() >= other.ordinal();
	}

	/** The constant with the given id (case-insensitive), or empty for an unknown id. */
	public static Optional<SbomLevel> find(String value) {
		if (value != null) {
			for (SbomLevel candidate : values()) {
				if (candidate.id.equalsIgnoreCase(value.trim())) {
					return Optional.of(candidate);
				}
			}
		}
		return Optional.empty();
	}
}
