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
package org.gecko.bnd.sbom.model;

/**
 * Where in the runtime a component sits. A bundle in {@code -runbundles} is installed into the
 * framework and can be updated there; the framework ({@code -runfw}) and everything on
 * {@code -runpath} are on the framework's class path — they ship with the launch and are only
 * replaced by rebuilding it. That matters when assessing a vulnerability.
 */
public enum SbomLayer {

	/** installed bundle ({@code -runbundles}) */
	RUNBUNDLE("runbundle"),
	/** the OSGi framework ({@code -runfw}) */
	RUNFW("runfw"),
	/** framework class path ({@code -runpath}) */
	RUNPATH("runpath");

	private final String id;

	SbomLayer(String id) {
		this.id = id;
	}

	/** value of the {@code osgi:layer} property */
	public String id() {
		return id;
	}
}
