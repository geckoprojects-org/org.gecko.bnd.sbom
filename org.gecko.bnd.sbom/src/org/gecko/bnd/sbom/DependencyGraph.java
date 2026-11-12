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
package org.gecko.bnd.sbom;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.jar.Manifest;

import org.gecko.bnd.sbom.model.SbomComponent;
import org.osgi.framework.namespace.ExecutionEnvironmentNamespace;
import org.osgi.resource.Capability;
import org.osgi.resource.Namespace;
import org.osgi.resource.Requirement;
import org.osgi.resource.Resource;

import aQute.bnd.header.Parameters;
import aQute.bnd.osgi.Domain;
import aQute.bnd.osgi.resource.CapReqBuilder;
import aQute.bnd.osgi.resource.ResourceBuilder;
import aQute.bnd.osgi.resource.ResourceUtils;
import aQute.bnd.version.Version;

/**
 * The dependency graph of the resolved application (#13), computed from the manifests of the
 * resolved bundles and the framework.
 * <p>
 * Every requirement a bundle declares in its manifest that the resolver acts on —
 * {@code Import-Package}, {@code Require-Bundle}, {@code Fragment-Host},
 * {@code Require-Capability} with {@code effective:=resolve} — is matched against the
 * capabilities of the other components. A match is an edge: A depends on B because B provides
 * what A requires. Edges are only drawn within the resolved set, so the graph is the one of the
 * checked-in {@code -runbundles}, not of a new resolution.
 * <ul>
 * <li>A requirement the bundle satisfies itself (it imports what it exports) gives no edge.</li>
 * <li>With several providers the highest capability version is taken, as the resolver prefers
 * it; the graph is an approximation of the framework's wiring there.</li>
 * <li>Not drawn: {@code osgi.ee} (the Java runtime), {@code DynamicImport-Package}, requirements
 * with {@code effective:=active} (services), and packages nobody in the set exports (system
 * packages of the JDK) — these stay declared as known unknowns.</li>
 * </ul>
 * The application depends on the components that satisfy {@code -runrequires}, or on all
 * bundles when it names none of them, and on the framework.
 */
public final class DependencyGraph {

	private final Map<SbomComponent, Resource>	resources	= new LinkedHashMap<>();

	/**
	 * @param manifests the components of the application with their manifests; components
	 *            without a manifest take part as neither consumer nor provider
	 */
	public DependencyGraph(Map<SbomComponent, Manifest> manifests) {
		for (Map.Entry<SbomComponent, Manifest> entry : manifests.entrySet()) {
			if (entry.getValue() == null) {
				continue;
			}
			ResourceBuilder builder = new ResourceBuilder();
			if (builder.addManifest(Domain.domain(entry.getValue()))) {
				resources.put(entry.getKey(), builder.build());
			}
		}
	}

	/** For each component the components it depends on, in model order. */
	public Map<SbomComponent, Set<SbomComponent>> edges() {
		Map<SbomComponent, Set<SbomComponent>> edges = new LinkedHashMap<>();
		for (Map.Entry<SbomComponent, Resource> consumer : resources.entrySet()) {
			Set<SbomComponent> dependsOn = new LinkedHashSet<>();
			for (Requirement requirement : consumer.getValue()
				.getRequirements(null)) {
				if (!isWired(requirement)) {
					continue;
				}
				provider(consumer.getKey(), consumer.getValue(), requirement).ifPresent(dependsOn::add);
			}
			edges.put(consumer.getKey(), dependsOn);
		}
		return edges;
	}

	/**
	 * The components the application itself depends on: those that satisfy {@code -runrequires},
	 * all components when none does or none is given.
	 *
	 * @param runRequires the {@code -runrequires} instruction, may be {@code null}
	 */
	public Set<SbomComponent> roots(String runRequires) {
		Set<SbomComponent> roots = new LinkedHashSet<>();
		if (runRequires != null && !runRequires.isBlank()) {
			for (Requirement requirement : CapReqBuilder.getRequirementsFrom(new Parameters(runRequires))) {
				for (Map.Entry<SbomComponent, Resource> entry : resources.entrySet()) {
					if (ResourceUtils.matches(requirement, entry.getValue())) {
						roots.add(entry.getKey());
					}
				}
			}
		}
		if (roots.isEmpty()) {
			roots.addAll(resources.keySet());
		}
		return roots;
	}

	/** Requirements the resolver wires; see the class comment for what is left out. */
	private static boolean isWired(Requirement requirement) {
		String namespace = requirement.getNamespace();
		if (ExecutionEnvironmentNamespace.EXECUTION_ENVIRONMENT_NAMESPACE.equals(namespace)) {
			return false;
		}
		if (!Namespace.EFFECTIVE_RESOLVE.equals(ResourceUtils.getEffective(requirement.getDirectives()))) {
			return false;
		}
		// DynamicImport-Package has resolution:=dynamic, which is neither mandatory nor optional
		return ResourceUtils.getResolution(requirement) != null;
	}

	private Optional<SbomComponent> provider(SbomComponent consumer, Resource consumerResource,
		Requirement requirement) {
		if (ResourceUtils.matches(requirement, consumerResource)) {
			return Optional.empty(); // substitutable export: the bundle wires to itself
		}
		List<Candidate> candidates = new ArrayList<>();
		for (Map.Entry<SbomComponent, Resource> entry : resources.entrySet()) {
			if (entry.getKey() == consumer) {
				continue;
			}
			for (Capability capability : entry.getValue()
				.getCapabilities(requirement.getNamespace())) {
				if (ResourceUtils.matches(requirement, capability)) {
					candidates.add(new Candidate(entry.getKey(), version(capability), candidates.size()));
				}
			}
		}
		return candidates.stream()
			.max(Comparator.comparing(Candidate::version)
				.thenComparing(Comparator.comparingInt(Candidate::order)
					.reversed()))
			.map(Candidate::component);
	}

	private static Version version(Capability capability) {
		Version version = ResourceUtils.getVersion(capability);
		return version != null ? version : Version.emptyVersion;
	}

	private record Candidate(SbomComponent component, Version version, int order) {}
}
