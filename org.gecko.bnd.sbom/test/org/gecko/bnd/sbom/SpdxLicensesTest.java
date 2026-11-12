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

import org.gecko.bnd.sbom.SpdxLicenses;

/**
 * Unit tests for the SPDX id normalizer (pure logic).
 */
public class SpdxLicensesTest {

	@Test
	public void recognizesExactSpdxId() {
		assertThat(SpdxLicenses.toId("Apache-2.0")).isEqualTo("Apache-2.0");
		assertThat(SpdxLicenses.toId("MIT")).isEqualTo("MIT");
	}

	@Test
	public void isCaseInsensitiveButReturnsCanonicalCasing() {
		assertThat(SpdxLicenses.toId("apache-2.0")).isEqualTo("Apache-2.0");
		assertThat(SpdxLicenses.toId("bsd-3-clause")).isEqualTo("BSD-3-Clause");
	}

	@Test
	public void parsesCanonicalOpensourceOrgUrl() {
		assertThat(SpdxLicenses.toId("https://opensource.org/licenses/EPL-2.0")).isEqualTo("EPL-2.0");
		assertThat(SpdxLicenses.toId("http://opensource.org/licenses/MIT/")).isEqualTo("MIT");
	}

	@Test
	public void mapsCommonNonOpensourceUrls() {
		assertThat(SpdxLicenses.toId("https://www.apache.org/licenses/LICENSE-2.0")).isEqualTo("Apache-2.0");
		assertThat(SpdxLicenses.toId("https://www.eclipse.org/legal/epl-v10.html")).isEqualTo("EPL-1.0");
	}

	@Test
	public void unknownReturnsNull() {
		assertThat(SpdxLicenses.toId("My Proprietary License")).isNull();
		assertThat(SpdxLicenses.toId("https://example.com/license")).isNull();
		assertThat(SpdxLicenses.toId(null)).isNull();
		assertThat(SpdxLicenses.toId("  ")).isNull();
	}
}
