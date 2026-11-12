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

	@Test
	public void mapsLicenseNamesSeenInManifestsAndPoms() {
		assertThat(SpdxLicenses.toId("Eclipse Public License 2.0")).isEqualTo("EPL-2.0");
		assertThat(SpdxLicenses.toId("Eclipse Public License - v 2.0")).isEqualTo("EPL-2.0");
		assertThat(SpdxLicenses.toId("Eclipse Public License, Version 2.0")).isEqualTo("EPL-2.0");
		assertThat(SpdxLicenses.toId("Eclipse Public License - v 1.0")).isEqualTo("EPL-1.0");
		assertThat(SpdxLicenses.toId("The Apache Software License, Version 2.0")).isEqualTo("Apache-2.0");
		assertThat(SpdxLicenses.toId("Apache License, Version 2.0")).isEqualTo("Apache-2.0");
		assertThat(SpdxLicenses.toId("The MIT License")).isEqualTo("MIT");
		assertThat(SpdxLicenses.toId("Eclipse Distribution License - v 1.0")).isEqualTo("BSD-3-Clause");
	}

	@Test
	public void mapsLicenseUrlsSeenInManifests() {
		assertThat(SpdxLicenses.toId("https://opensource.org/license/mit")).isEqualTo("MIT");
		assertThat(SpdxLicenses.toId("http://www.opensource.org/licenses/mit-license.php")).isEqualTo("MIT");
		assertThat(SpdxLicenses.toId("http://www.apache.org/licenses/LICENSE-2.0.txt")).isEqualTo("Apache-2.0");
		assertThat(SpdxLicenses.toId("http://www.eclipse.org/legal/epl-v20.html")).isEqualTo("EPL-2.0");
		assertThat(SpdxLicenses.toId("https://www.eclipse.org/org/documents/epl-2.0/EPL-2.0.txt")).isEqualTo("EPL-2.0");
		assertThat(SpdxLicenses.toId("http://www.eclipse.org/org/documents/edl-v10.php")).isEqualTo("BSD-3-Clause");
	}

	@Test
	public void ambiguousNamesStayUnmapped() {
		assertThat(SpdxLicenses.toExpression("GNU Lesser General Public License")).isNull();
		assertThat(SpdxLicenses.toExpression("BSD License")).isNull();
		assertThat(SpdxLicenses.toExpression("http://www.opensource.org/licenses/bsd-license.php")).isNull();
	}

	@Test
	public void recognizesExpressionsOfKnownIds() {
		assertThat(SpdxLicenses.toExpression("(Apache-2.0 OR EPL-2.0)")).isEqualTo("(Apache-2.0 OR EPL-2.0)");
		assertThat(SpdxLicenses.toExpression("apache-2.0 or epl-2.0")).isEqualTo("Apache-2.0 OR EPL-2.0");
		assertThat(SpdxLicenses.toExpression("GPL-2.0-only WITH Classpath-exception-2.0"))
			.isEqualTo("GPL-2.0-only WITH Classpath-exception-2.0");
		assertThat(SpdxLicenses.toExpression("MIT AND LicenseRef-Vendor")).isEqualTo("MIT AND LicenseRef-Vendor");
		// an expression is not a single id
		assertThat(SpdxLicenses.toId("(Apache-2.0 OR EPL-2.0)")).isNull();
	}

	@Test
	public void rejectsInvalidExpressions() {
		assertThat(SpdxLicenses.toExpression("(Apache-2.0 OR EPL-2.0")).isNull();
		assertThat(SpdxLicenses.toExpression("Apache-2.0 OR")).isNull();
		assertThat(SpdxLicenses.toExpression("Apache-2.0 OR Mystery-1.0")).isNull();
		assertThat(SpdxLicenses.toExpression("MIT WITH Apache-2.0")).isNull();
		assertThat(SpdxLicenses.toExpression("Apache-2.0 EPL-2.0")).isNull();
	}
}
