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

import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Deterministic references to the application and its components, shared by all serializers
 * (CycloneDX {@code bom-ref}, SPDX {@code SPDXID}).
 * <p>
 * A component is referenced by its PURL, or by {@code bsn@version} when it has no verified Maven
 * identity; the application by its name. The same model therefore always yields the same
 * references, which keeps BOMs of unchanged applications identical and diffs between builds
 * meaningful. Should two components still collide, the later ones get a {@code #2}, {@code #3},
 * … suffix in model order.
 */
public final class SbomRefs {

	/** Reserved by SPDX for the document itself. */
	public static final String					SPDX_DOCUMENT	= "SPDXRef-DOCUMENT";

	private static final String					SPDX_PREFIX		= "SPDXRef-";

	private final String						application;
	private final String						spdxApplication;
	private final Map<SbomComponent, String>	refs			= new IdentityHashMap<>();
	private final Map<SbomComponent, String>	spdxRefs		= new IdentityHashMap<>();

	private SbomRefs(SbomModel model) {
		Set<String> used = new HashSet<>();
		Set<String> spdxUsed = new HashSet<>();
		spdxUsed.add(SPDX_DOCUMENT);

		String applicationName = model.getApplicationName() != null ? model.getApplicationName() : "application";
		application = unique(applicationName, used, "#");
		spdxApplication = unique(SPDX_PREFIX + spdxSafe(applicationName), spdxUsed, "-");

		for (SbomComponent component : model.getComponents()) {
			String base = base(component);
			refs.put(component, unique(base, used, "#"));
			spdxRefs.put(component, unique(SPDX_PREFIX + spdxSafe(base), spdxUsed, "-"));
		}
	}

	public static SbomRefs of(SbomModel model) {
		return new SbomRefs(model);
	}

	/** {@code bom-ref} of the application ({@code metadata.component}). */
	public String application() {
		return application;
	}

	/** {@code SPDXID} of the application. */
	public String spdxApplication() {
		return spdxApplication;
	}

	/** {@code bom-ref} of a component of the model. */
	public String of(SbomComponent component) {
		return require(refs, component);
	}

	/** {@code SPDXID} of a component of the model ({@code SPDXRef-} + letters, digits, '.', '-'). */
	public String spdxOf(SbomComponent component) {
		return require(spdxRefs, component);
	}

	private static String base(SbomComponent component) {
		if (component.getPurl() != null) {
			return component.getPurl();
		}
		String bsn = component.getBsn() != null ? component.getBsn() : "component";
		return component.getVersion() != null ? bsn + "@" + component.getVersion() : bsn;
	}

	private static String unique(String base, Set<String> used, String separator) {
		String candidate = base;
		for (int n = 2; !used.add(candidate); n++) {
			candidate = base + separator + n;
		}
		return candidate;
	}

	/** SPDX element ids allow only letters, digits, '.' and '-'. */
	private static String spdxSafe(String value) {
		return value.replaceAll("[^A-Za-z0-9.-]", "-");
	}

	private static String require(Map<SbomComponent, String> map, SbomComponent component) {
		String ref = map.get(component);
		if (ref == null) {
			throw new IllegalArgumentException("Component is not part of the model: " + component.getBsn());
		}
		return ref;
	}
}
