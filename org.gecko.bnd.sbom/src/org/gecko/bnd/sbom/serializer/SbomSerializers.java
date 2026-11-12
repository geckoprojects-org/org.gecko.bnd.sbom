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

/**
 * Selects the {@link SbomSerializer} for the configured {@link SbomFormat}.
 */
public final class SbomSerializers {

	private SbomSerializers() {}

	public static SbomSerializer forFormat(SbomFormat format) {
		switch (format) {
			case CYCLONEDX :
				return new CycloneDxSerializer();
			case SPDX :
				return new SpdxSerializer();
			default :
				throw new IllegalArgumentException("Unknown SBOM format: " + format);
		}
	}
}
