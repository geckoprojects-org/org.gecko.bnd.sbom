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
 * The result of a check for one application (one SBOM).
 *
 * @param application the application, as named in the SBOM
 * @param proposals one per vulnerable library, in the order of the SBOM
 */
public record CheckReport(String application, List<Proposal> proposals) {

	public CheckReport {
		proposals = List.copyOf(proposals);
	}

	public List<Proposal> withStatus(Proposal.Status status) {
		return proposals.stream()
			.filter(p -> p.status() == status)
			.toList();
	}
}
