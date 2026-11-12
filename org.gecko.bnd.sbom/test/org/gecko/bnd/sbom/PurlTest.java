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

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import org.gecko.bnd.sbom.Purl;

/**
 * Unit tests for the {@code pkg:maven} PURL builder (pure string logic, no workspace).
 */
public class PurlTest {

	@Test
	public void buildsPlainMavenPurl() {
		assertThat(Purl.maven("com.example", "foo", "1.2.3", null, null))
			.isEqualTo("pkg:maven/com.example/foo@1.2.3");
	}

	@Test
	public void incompleteCoordinateYieldsNullNotFakePurl() {
		assertThat(Purl.maven(null, "foo", "1.2.3", null, null)).isNull();
		assertThat(Purl.maven("com.example", "", "1.2.3", null, null)).isNull();
		assertThat(Purl.maven("com.example", "foo", null, null, null)).isNull();
	}

	@Test
	public void jarExtensionIsDefaultAndOmitted() {
		assertThat(Purl.maven("com.example", "foo", "1.2.3", null, "jar"))
			.isEqualTo("pkg:maven/com.example/foo@1.2.3");
	}

	@Test
	public void classifierAndNonDefaultTypeBecomeQualifiersSortedByKey() {
		assertThat(Purl.maven("com.example", "foo", "1.2.3", "sources", "zip"))
			.isEqualTo("pkg:maven/com.example/foo@1.2.3?classifier=sources&type=zip");
	}

	@Test
	public void percentEncodesReservedCharacters() {
		// space and '+' are not in the unreserved set and must be percent-encoded
		assertThat(Purl.maven("com.example", "foo", "1.0 beta+1", null, null))
			.isEqualTo("pkg:maven/com.example/foo@1.0%20beta%2B1");
	}
}
