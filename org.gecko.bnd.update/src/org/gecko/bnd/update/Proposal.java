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

import java.util.List;

import aQute.bnd.version.MavenVersion;

/**
 * The result of checking one vulnerable library.
 *
 * @param library the installed library
 * @param vulnerabilities what is reported for it
 * @param locations where it sits (runbundle, framework, embedded in a bundle)
 * @param allowed the scope the version policy allows for it
 * @param proposed the smallest version within {@code allowed} that fixes all vulnerabilities;
 *            {@code null} if there is none
 * @param needed the smallest scope in which an available version fixes all vulnerabilities;
 *            {@code null} if no available version does
 */
public record Proposal(Library library, List<Vulnerability> vulnerabilities, List<Location> locations, Scope allowed,
	MavenVersion proposed, Scope needed) {

	public Proposal {
		vulnerabilities = List.copyOf(vulnerabilities);
		locations = List.copyOf(locations);
	}

	public enum Status {
		/** an update within the version policy fixes everything */
		UPDATE,
		/** a fix is available, but only in a larger scope than the policy allows */
		OUTSIDE_POLICY,
		/** no available version fixes all vulnerabilities */
		NO_FIX
	}

	public Status status() {
		if (proposed != null) {
			return Status.UPDATE;
		}
		return needed != null ? Status.OUTSIDE_POLICY : Status.NO_FIX;
	}
}
