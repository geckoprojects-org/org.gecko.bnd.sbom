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
package org.gecko.bnd.sbom.serializer;

import java.util.Optional;

/**
 * Output format, orthogonal to the {@link org.gecko.bnd.sbom.model.SbomLevel levels}
 * (requirements Q1). CycloneDX is the first serializer; SPDX follows (medium/BSI).
 */
public enum SbomFormat {

	CYCLONEDX("cyclonedx"),
	SPDX("spdx");

	private final String id;

	SbomFormat(String id) {
		this.id = id;
	}

	public String id() {
		return id;
	}

	/** The constant with the given id (case-insensitive), or empty for an unknown id. */
	public static Optional<SbomFormat> find(String value) {
		if (value != null) {
			for (SbomFormat candidate : values()) {
				if (candidate.id.equalsIgnoreCase(value.trim())) {
					return Optional.of(candidate);
				}
			}
		}
		return Optional.empty();
	}
}
