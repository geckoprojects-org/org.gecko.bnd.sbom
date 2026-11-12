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
package org.gecko.bnd.update.maven.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import java.util.List;

import org.gecko.bnd.update.CheckReport;
import org.gecko.bnd.update.Library;
import org.gecko.bnd.update.Proposal;
import org.gecko.bnd.update.Scope;
import org.gecko.bnd.update.Vulnerability;
import org.junit.jupiter.api.Test;

import aQute.bnd.version.MavenVersion;

public class VulnerabilitiesMojoTest {

	private static Proposal proposal(String artifact, MavenVersion proposed, Scope needed) {
		return new Proposal(new Library("g", artifact, "1.0.0"),
			List.of(new Vulnerability("CVE-1", "HIGH", List.of("1.0.1"), null)), List.of(), Scope.MICRO, proposed,
			needed);
	}

	@Test
	public void failOn() {
		CheckReport fixable = new CheckReport("app",
			List.of(proposal("a", new MavenVersion("1.0.1"), Scope.MICRO)));
		CheckReport unfixable = new CheckReport("app", List.of(proposal("a", new MavenVersion("1.0.1"), Scope.MICRO),
			proposal("b", null, Scope.MINOR)));
		CheckReport clean = new CheckReport("app", List.of());

		assertThat(VulnerabilitiesMojo.failure(unfixable, "none")).isNull();
		assertThat(VulnerabilitiesMojo.failure(fixable, "unfixable")).isNull();
		assertThat(VulnerabilitiesMojo.failure(unfixable, "unfixable")).contains("1 vulnerable libraries without a fix");
		assertThat(VulnerabilitiesMojo.failure(fixable, "vulnerable")).contains("1 vulnerable");
		assertThat(VulnerabilitiesMojo.failure(clean, "vulnerable")).isNull();
		assertThatIllegalArgumentException().isThrownBy(() -> VulnerabilitiesMojo.failure(clean, "sometimes"));
	}
}
