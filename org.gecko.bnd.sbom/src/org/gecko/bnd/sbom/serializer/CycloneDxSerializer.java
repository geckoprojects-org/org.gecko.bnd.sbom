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
package org.gecko.bnd.sbom.serializer;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.gecko.bnd.sbom.SbomConfig;
import org.gecko.bnd.sbom.model.MavenCoordinates;
import org.gecko.bnd.sbom.model.SbomComponent;
import org.gecko.bnd.sbom.model.SbomLicense;
import org.gecko.bnd.sbom.model.SbomModel;
import org.gecko.bnd.sbom.model.SbomRefs;
import org.gecko.bnd.sbom.model.SbomTool;
import aQute.bnd.osgi.EmbeddedResource;
import aQute.bnd.osgi.Resource;
import aQute.lib.json.JSONCodec;

/**
 * Serializes the {@link SbomModel} as CycloneDX JSON (first serializer, see Q1). Builds the
 * BOM tree as {@code Map}/{@code List} and encodes it with bnd's own {@link JSONCodec} —
 * deliberately without an external CycloneDX library in the skeleton.
 * <p>
 * Skeleton scope: {@code simple} fields + (medium) hash/filename/license. The format-native
 * OSGi constructs ({@code pedigree}, {@code properties} for {@code includeOSGIMetadata}) are
 * marked as TODO.
 */
public final class CycloneDxSerializer implements SbomSerializer {

	private static final JSONCodec	CODEC			= new JSONCodec();

	/** Bundle-SymbolicName of a component. */
	public static final String		PROPERTY_BSN			= "osgi:bundle:symbolicName";
	/** OSGi Bundle-Version of a component (the Maven version is the component's version). */
	public static final String		PROPERTY_BUNDLE_VERSION	= "osgi:bundle:version";

	@Override
	public String fileExtension() {
		return ".cdx.json";
	}

	@Override
	public Resource serialize(SbomModel model, SbomConfig config) throws Exception {
		Map<String, Object> bom = new LinkedHashMap<>();
		// #17: the selected specification version, with its schema so editors and CI can validate
		bom.put("$schema", "http://cyclonedx.org/schema/bom-" + config.cyclonedxVersion() + ".schema.json");
		bom.put("bomFormat", "CycloneDX");
		bom.put("specVersion", config.cyclonedxVersion());
		SbomRefs refs = SbomRefs.of(model);
		// #12: identity of this BOM; together with version it tells a new BOM from a revision
		bom.put("serialNumber", SerialNumbers.urn(SerialNumbers.of(model, refs, config)));
		bom.put("version", 1);
		bom.put("metadata", metadata(model, config, refs));

		List<Object> components = new ArrayList<>();
		for (SbomComponent component : model.getComponents()) {
			components.add(component(component, refs));
		}
		bom.put("components", components);

		// #13: the dependency graph — every component, so that "no dependencies" is stated too
		if (model.hasDependencyGraph()) {
			bom.put("dependencies", dependencies(model, refs));
		}

		// A2.5/Q4: completeness + declared "known unknowns".
		bom.put("compositions", compositions(model, refs));

		String json = CODEC.enc()
			.indent("  ")
			.put(bom)
			.toString();

		return new EmbeddedResource(json, config.created()
			.toEpochMilli());
	}

	private Map<String, Object> metadata(SbomModel model, SbomConfig config, SbomRefs refs) {
		Map<String, Object> metadata = new LinkedHashMap<>();
		metadata.put("timestamp", config.created()
			.toString());

		Map<String, Object> tools = new LinkedHashMap<>();
		tools.put("components", tools(model));
		metadata.put("tools", tools);

		// #15: the application with its identity and where it comes from
		Map<String, Object> app = new LinkedHashMap<>();
		app.put("bom-ref", refs.application());
		app.put("type", "application");
		putIfPresent(app, "group", model.getApplicationGroup());
		app.put("name", model.getApplicationName());
		putIfPresent(app, "version", model.getApplicationVersion());
		putIfPresent(app, "purl", model.getApplicationPurl());
		List<Object> references = new ArrayList<>();
		if (model.getVcsUrl() != null) {
			references.add(reference("vcs", model.getVcsUrl()));
		}
		if (model.getWebsiteUrl() != null) {
			references.add(reference("website", model.getWebsiteUrl()));
		}
		if (!references.isEmpty()) {
			app.put("externalReferences", references);
		}
		metadata.put("component", app);

		// The build's own properties (property.<name> in -sbom: commit, image reference), then
		// A2.5/Q4: why the BOM is incomplete — compositions may not carry properties (schema), so
		// the declared gaps go here as well.
		List<Object> properties = new ArrayList<>();
		model.getProperties()
			.forEach((name, value) -> properties.add(property(name, value)));
		for (String unknown : model.getKnownUnknowns()) {
			properties.add(property("osgi:known-unknown", unknown));
		}
		if (!properties.isEmpty()) {
			metadata.put("properties", properties);
		}
		return metadata;
	}

	/** The tools of the model; without any (a model built by hand) this exporter by name. */
	private static List<Object> tools(SbomModel model) {
		List<Object> result = new ArrayList<>();
		for (SbomTool tool : model.getTools()) {
			Map<String, Object> node = new LinkedHashMap<>();
			node.put("type", "application");
			if (tool.manufacturer() != null) {
				node.put("manufacturer", singletonMap("name", tool.manufacturer()));
			}
			putIfPresent(node, "group", tool.group());
			node.put("name", tool.name());
			putIfPresent(node, "version", tool.version());
			putIfPresent(node, "purl", tool.purl());
			result.add(node);
		}
		if (result.isEmpty()) {
			Map<String, Object> node = new LinkedHashMap<>();
			node.put("type", "application");
			node.put("name", "org.gecko.bnd.sbom");
			result.add(node);
		}
		return result;
	}

	private static List<Object> dependencies(SbomModel model, SbomRefs refs) {
		List<Object> result = new ArrayList<>();
		result.add(dependency(refs.application(), model.getApplicationDependencies(), refs));
		for (SbomComponent component : model.getComponents()) {
			result.add(dependency(refs.of(component), model.getDependencies(component), refs));
		}
		return result;
	}

	private static Map<String, Object> dependency(String ref, Iterable<SbomComponent> dependsOn, SbomRefs refs) {
		Map<String, Object> node = new LinkedHashMap<>();
		node.put("ref", ref);
		List<Object> targets = new ArrayList<>();
		for (SbomComponent target : dependsOn) {
			targets.add(refs.of(target));
		}
		node.put("dependsOn", targets);
		return node;
	}

	private static Map<String, Object> reference(String type, String url) {
		Map<String, Object> reference = new LinkedHashMap<>();
		reference.put("type", type);
		reference.put("url", url);
		return reference;
	}

	private Map<String, Object> component(SbomComponent component, SbomRefs refs) {
		Map<String, Object> node = new LinkedHashMap<>();
		node.put("bom-ref", refs.of(component));
		node.put("type", "library");
		// Name and version agree with the PURL: Maven coordinates when verified, otherwise the
		// OSGi identity (#14).
		MavenCoordinates maven = component.getMaven();
		if (maven != null) {
			node.put("group", maven.groupId());
			node.put("name", maven.artifactId());
			node.put("version", maven.version());
		} else {
			node.put("name", component.getBsn());
			putIfPresent(node, "version", component.getVersion());
		}
		putIfPresent(node, "purl", component.getPurl());

		if (component.getSha512() != null) {
			Map<String, Object> hash = new LinkedHashMap<>();
			hash.put("alg", "SHA-512");
			hash.put("content", component.getSha512());
			node.put("hashes", listOf(hash));
		}
		List<Object> licenses = licenses(component.getLicenses());
		if (!licenses.isEmpty()) {
			node.put("licenses", licenses);
		}
		putIfPresent(node, "publisher", component.getSupplier());

		List<Object> properties = new ArrayList<>();
		// The OSGi identity is what the framework sees; it must not get lost behind the Maven one.
		if (component.getBsn() != null) {
			properties.add(property(PROPERTY_BSN, component.getBsn()));
		}
		if (component.getVersion() != null) {
			properties.add(property(PROPERTY_BUNDLE_VERSION, component.getVersion()));
		}
		// Q3.b: flag an unresolvable identity honestly instead of inventing a PURL.
		if (component.isUnverifiedIdentity()) {
			properties.add(property("osgi:identity:matchability", "unverified"));
		}
		if (!properties.isEmpty()) {
			node.put("properties", properties);
		}
		// TODO(includeOSGIMetadata): Import-Package ranges / Require-Capability as namespaced
		//   properties; package/class provenance format-natively via CycloneDX `pedigree`.
		return node;
	}

	/**
	 * CycloneDX distinguishes a validated SPDX id ({@code license.id}) from free text
	 * ({@code license.name}); an SPDX expression is a single {@code expression} entry, which may
	 * not be mixed with license entries. Several ids and expressions therefore become one
	 * expression joined with AND; only together with free text, which an expression cannot hold,
	 * does an expression fall back to {@code license.name}.
	 */
	private static List<Object> licenses(List<SbomLicense> licenses) {
		List<Object> result = new ArrayList<>();
		boolean anyExpression = licenses.stream()
			.anyMatch(SbomLicense::isExpression);
		boolean anyName = licenses.stream()
			.anyMatch(l -> !l.isSpdx() && !l.isExpression());
		if (anyExpression && !anyName) {
			String expression = licenses.size() == 1 ? licenses.get(0)
				.expression()
				: licenses.stream()
					.map(SbomLicense::asOperand)
					.collect(Collectors.joining(" AND "));
			result.add(singletonMap("expression", expression));
			return result;
		}
		for (SbomLicense license : licenses) {
			Map<String, Object> value = license.isSpdx() ? singletonMap("id", license.spdxId())
				: singletonMap("name", license.isExpression() ? license.expression() : license.name());
			result.add(singletonMap("license", value));
		}
		return result;
	}

	private List<Object> compositions(SbomModel model, SbomRefs refs) {
		Map<String, Object> composition = new LinkedHashMap<>();
		composition.put("aggregate", model.isDependenciesComplete() ? "complete" : "incomplete");
		// the statement is about the application's assembly: the components listed in this BOM
		composition.put("assemblies", listOf(refs.application()));
		return listOf(composition);
	}

	private static void putIfPresent(Map<String, Object> node, String key, String value) {
		if (value != null) {
			node.put(key, value);
		}
	}

	private static Map<String, Object> property(String name, String value) {
		Map<String, Object> property = new LinkedHashMap<>();
		property.put("name", name);
		property.put("value", value);
		return property;
	}

	private static Map<String, Object> singletonMap(String key, Object value) {
		Map<String, Object> map = new LinkedHashMap<>();
		map.put(key, value);
		return map;
	}

	private static List<Object> listOf(Object element) {
		List<Object> list = new ArrayList<>();
		list.add(element);
		return list;
	}
}
