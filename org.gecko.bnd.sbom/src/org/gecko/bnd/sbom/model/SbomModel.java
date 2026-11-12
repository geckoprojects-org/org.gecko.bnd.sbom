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

import java.util.ArrayList;
import java.util.List;

/**
 * Format-neutral SBOM root model of the resolved application (View 2). Populated by an
 * {@code SbomModelBuilder} and translated into a concrete format (CycloneDX/SPDX) by an
 * {@code SbomSerializer}.
 */
public final class SbomModel {

	private String						applicationName;
	private final List<SbomComponent>	components		= new ArrayList<>();
	/**
	 * Explicitly declared gaps (Q4/A2.5): e.g. boot delegation, {@code DynamicImport-Package},
	 * unresolvable identities. Emitted in the SBOM as a completeness caveat.
	 */
	private final List<String>			knownUnknowns	= new ArrayList<>();
	/** {@code true} when all dependencies were captured reliably (medium+, A2.5). */
	private boolean						dependenciesComplete;

	public String getApplicationName() {
		return applicationName;
	}

	public SbomModel setApplicationName(String applicationName) {
		this.applicationName = applicationName;
		return this;
	}

	public List<SbomComponent> getComponents() {
		return components;
	}

	public SbomModel addComponent(SbomComponent component) {
		components.add(component);
		return this;
	}

	public List<String> getKnownUnknowns() {
		return knownUnknowns;
	}

	public SbomModel addKnownUnknown(String description) {
		knownUnknowns.add(description);
		return this;
	}

	public boolean isDependenciesComplete() {
		return dependenciesComplete;
	}

	public SbomModel setDependenciesComplete(boolean dependenciesComplete) {
		this.dependenciesComplete = dependenciesComplete;
		return this;
	}
}
