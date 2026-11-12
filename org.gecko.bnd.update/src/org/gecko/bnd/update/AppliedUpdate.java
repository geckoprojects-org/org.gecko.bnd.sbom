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

/**
 * What happened to one update.
 *
 * @param update the update
 * @param status see {@link Status}
 * @param reason why it was not applied or reverted; {@code null} when applied
 */
public record AppliedUpdate(Update update, Status status, String reason) {

	public enum Status {
		/** applied; every bndrun resolves (and the build passed, if one ran) */
		APPLIED,
		/** applied, then reverted: a bndrun no longer resolves or the build failed */
		REVERTED,
		/** not applied: the version comes from a macro in the index ({@code ${bndversion}}) */
		SKIPPED_MACRO,
		/** not applied: the library is not in a {@code .mvn} index (embedded, or pom index) */
		NOT_IN_INDEX,
		/** not applied: the policy allows no update for it */
		NOT_PROPOSED,
		/** not applied: the workspace does not resolve even without updates */
		NOT_APPLIED
	}
}
