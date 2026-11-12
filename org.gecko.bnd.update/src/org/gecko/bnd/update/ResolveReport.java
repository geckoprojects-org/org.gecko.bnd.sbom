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
 * The outcome of resolving the bndruns of a workspace.
 */
public record ResolveReport(List<BndrunResult> results) {

	public ResolveReport {
		results = List.copyOf(results);
	}

	/** {@code true} if every bndrun resolves (changed or not). */
	public boolean allResolve() {
		return results.stream()
			.allMatch(BndrunResult::resolves);
	}

	public List<BndrunResult> withStatus(BndrunResult.Status status) {
		return results.stream()
			.filter(r -> r.status() == status)
			.toList();
	}
}
