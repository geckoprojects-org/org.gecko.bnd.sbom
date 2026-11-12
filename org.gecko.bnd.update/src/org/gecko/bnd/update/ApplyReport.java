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

/**
 * The result of applying updates.
 *
 * @param mode how they were applied
 * @param updates what happened to each update
 * @param resolve the final resolution of all bndruns (after the kept updates)
 * @param build the final build, {@code null} if none ran
 * @param baseline the resolution before any update; when it fails, nothing was applied
 */
public record ApplyReport(UpdateApplier.Mode mode, List<AppliedUpdate> updates, ResolveReport resolve,
	BuildStep.Result build, ResolveReport baseline) {

	public ApplyReport {
		updates = List.copyOf(updates);
	}

	public List<AppliedUpdate> withStatus(AppliedUpdate.Status status) {
		return updates.stream()
			.filter(u -> u.status() == status)
			.toList();
	}

	/** {@code true} if at least one update was applied and kept. */
	public boolean anyApplied() {
		return !withStatus(AppliedUpdate.Status.APPLIED).isEmpty();
	}

	/**
	 * {@code true} if the workspace did not resolve before any update — then no update was
	 * tried: a failure could not be told apart from one the updates cause. Typically the
	 * workspace's own bundles are not built.
	 */
	public boolean baselineFails() {
		return baseline != null && !baseline.allResolve();
	}

	/** {@code true} if an update had to be reverted. */
	public boolean anyReverted() {
		return !withStatus(AppliedUpdate.Status.REVERTED).isEmpty();
	}
}
