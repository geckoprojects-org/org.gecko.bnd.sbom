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
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Format-neutral SBOM root model of the resolved application (View 2). Populated by an
 * {@code SbomModelBuilder} and translated into a concrete format (CycloneDX/SPDX) by an
 * {@code SbomSerializer}.
 */
public final class SbomModel {

	private String						applicationName;
	private String						applicationGroup;
	private String						applicationVersion;
	/** PURL of the application, if one was given ({@code application.purl}). */
	private String						applicationPurl;
	/** Free properties of the BOM ({@code property.<name>}), in the order given. */
	private final Map<String, String>	properties				= new LinkedHashMap<>();
	/** Source repository of the application (CycloneDX {@code vcs} reference). */
	private String						vcsUrl;
	/** Website of the application (CycloneDX {@code website}, SPDX {@code homepage}). */
	private String						websiteUrl;
	/**
	 * Dependency graph (#13): for each component the components it depends on; {@code null}
	 * when no graph was computed.
	 */
	private Map<SbomComponent, Set<SbomComponent>>	dependencies;
	/** The components the application itself depends on. */
	private final Set<SbomComponent>			applicationDependencies	= new LinkedHashSet<>();
	/** The tools that write this SBOM. */
	private final List<SbomTool>		tools			= new ArrayList<>();
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

	public String getApplicationGroup() {
		return applicationGroup;
	}

	public SbomModel setApplicationGroup(String applicationGroup) {
		this.applicationGroup = applicationGroup;
		return this;
	}

	public String getApplicationVersion() {
		return applicationVersion;
	}

	public SbomModel setApplicationVersion(String applicationVersion) {
		this.applicationVersion = applicationVersion;
		return this;
	}

	public String getApplicationPurl() {
		return applicationPurl;
	}

	public SbomModel setApplicationPurl(String applicationPurl) {
		this.applicationPurl = applicationPurl;
		return this;
	}

	public Map<String, String> getProperties() {
		return properties;
	}

	public SbomModel addProperty(String name, String value) {
		properties.put(name, value);
		return this;
	}

	public String getVcsUrl() {
		return vcsUrl;
	}

	public SbomModel setVcsUrl(String vcsUrl) {
		this.vcsUrl = vcsUrl;
		return this;
	}

	public String getWebsiteUrl() {
		return websiteUrl;
	}

	public SbomModel setWebsiteUrl(String websiteUrl) {
		this.websiteUrl = websiteUrl;
		return this;
	}

	public List<SbomTool> getTools() {
		return tools;
	}

	public SbomModel addTool(SbomTool tool) {
		tools.add(tool);
		return this;
	}

	/** {@code true} when a dependency graph was computed and should be written. */
	public boolean hasDependencyGraph() {
		return dependencies != null;
	}

	/** The components {@code component} depends on (empty without a graph). */
	public Set<SbomComponent> getDependencies(SbomComponent component) {
		if (dependencies == null) {
			return Set.of();
		}
		return dependencies.getOrDefault(component, Set.of());
	}

	public Set<SbomComponent> getApplicationDependencies() {
		return applicationDependencies;
	}

	/** Records that {@code from} depends on {@code to}; starts the graph if there is none. */
	public SbomModel addDependency(SbomComponent from, SbomComponent to) {
		dependencyGraph().computeIfAbsent(from, c -> new LinkedHashSet<>())
			.add(to);
		return this;
	}

	public SbomModel addApplicationDependency(SbomComponent to) {
		dependencyGraph();
		applicationDependencies.add(to);
		return this;
	}

	private Map<SbomComponent, Set<SbomComponent>> dependencyGraph() {
		if (dependencies == null) {
			dependencies = new LinkedHashMap<>();
		}
		return dependencies;
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
