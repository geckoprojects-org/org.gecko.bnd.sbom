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
import java.util.stream.Collectors;

/**
 * Updates that were reverted one by one ({@link UpdateApplier.Mode#EACH}) but fail on each
 * other: the old version of one pins the others to its own range (ASM modules require each
 * other in {@code [9.9.1,9.10.0)}), or one needs a newer version of another (Aries SPI Fly 1.3.8
 * needs ASM 9.10). Each of them alone breaks a bndrun; together they may not. A hint, not a
 * proof: retry them together with {@link UpdateApplier.Mode#ALL}.
 *
 * @param updates the updates of the group, in the order they were tried
 */
public record RevertedGroup(List<Update> updates) {

	public RevertedGroup {
		updates = List.copyOf(updates);
	}

	/** The libraries as {@code --only} takes them: {@code groupId:artifactId,…} */
	public String only() {
		return updates.stream()
			.map(u -> u.library()
				.ga())
			.distinct()
			.collect(Collectors.joining(","));
	}
}
