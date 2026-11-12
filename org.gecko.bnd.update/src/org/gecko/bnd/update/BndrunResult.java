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
 * The outcome of resolving one bndrun.
 *
 * @param bndrun path of the bndrun, relative to the workspace
 * @param status see {@link Status}
 * @param current the {@code -runbundles} in the file, as {@code bsn;version=range}
 * @param resolved what the resolver computes now; empty when it failed
 * @param added in {@code resolved}, not in {@code current}
 * @param removed in {@code current}, not in {@code resolved}
 * @param unresolved for a failed resolution: the requirements nothing satisfies, as
 *            {@code who -> namespace: filter}
 * @param message for a failed resolution or an error: the resolver's or bnd's message
 */
public record BndrunResult(String bndrun, Status status, List<String> current, List<String> resolved, List<String> added,
	List<String> removed, List<String> unresolved, String message) {

	public BndrunResult {
		current = List.copyOf(current);
		resolved = List.copyOf(resolved);
		added = List.copyOf(added);
		removed = List.copyOf(removed);
		unresolved = List.copyOf(unresolved);
	}

	public enum Status {
		/** resolves to exactly the {@code -runbundles} in the file */
		UNCHANGED,
		/** resolves, but to other {@code -runbundles} than in the file */
		CHANGED,
		/** does not resolve */
		FAILED,
		/** could not be evaluated (broken file, workspace error) */
		ERROR
	}

	public boolean resolves() {
		return status == Status.UNCHANGED || status == Status.CHANGED;
	}
}
