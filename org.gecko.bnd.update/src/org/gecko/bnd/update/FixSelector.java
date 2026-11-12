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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

import aQute.bnd.version.MavenVersion;
import aQute.bnd.version.Version;

/**
 * Picks the version that fixes a library's vulnerabilities.
 * <p>
 * A vulnerability lists one fixed version per maintained line, e.g. {@code 2.12.7.1, 2.13.4.2}:
 * versions below 2.12.7.1 are affected, and in the 2.13 line those below 2.13.4.2. A candidate
 * is taken as fixed when the highest fixed version not above it is in the candidate's own
 * major.minor line, or is the highest fixed version of all. So 2.12.8 and 2.13.5 are fixed,
 * 2.13.1 is not. Without range data from the advisory this is the closest reading of the list.
 */
public final class FixSelector {

	private FixSelector() {}

	/** {@code true} if {@code candidate} fixes the vulnerability with these fixed versions. */
	public static boolean fixes(MavenVersion candidate, Collection<String> fixedVersions) {
		List<MavenVersion> fixed = parse(fixedVersions);
		if (fixed.isEmpty()) {
			return false;
		}
		MavenVersion highest = fixed.get(fixed.size() - 1);
		MavenVersion floor = null;
		for (MavenVersion version : fixed) {
			if (version.compareTo(candidate) <= 0) {
				floor = version;
			}
		}
		if (floor == null) {
			return false;
		}
		return floor.equals(highest) || sameLine(floor, candidate);
	}

	/** {@code true} if {@code candidate} fixes all of the vulnerabilities. */
	public static boolean fixesAll(MavenVersion candidate, Collection<Vulnerability> vulnerabilities) {
		return vulnerabilities.stream()
			.allMatch(v -> fixes(candidate, v.fixedVersions()));
	}

	/**
	 * The smallest available version above {@code installed}, within {@code scope}, that fixes
	 * all vulnerabilities.
	 */
	public static Optional<MavenVersion> select(MavenVersion installed, Collection<Vulnerability> vulnerabilities,
		Collection<MavenVersion> available, Scope scope) {
		return available.stream()
			.filter(candidate -> scope.allows(installed, candidate))
			.filter(candidate -> fixesAll(candidate, vulnerabilities))
			.min(Comparator.naturalOrder());
	}

	private static boolean sameLine(MavenVersion a, MavenVersion b) {
		Version x = a.getOSGiVersion();
		Version y = b.getOSGiVersion();
		return x.getMajor() == y.getMajor() && x.getMinor() == y.getMinor();
	}

	private static List<MavenVersion> parse(Collection<String> versions) {
		List<MavenVersion> result = new ArrayList<>();
		for (String version : versions) {
			if (version != null && !version.isBlank()) {
				result.add(new MavenVersion(version.trim()));
			}
		}
		result.sort(Comparator.naturalOrder());
		return result;
	}
}
