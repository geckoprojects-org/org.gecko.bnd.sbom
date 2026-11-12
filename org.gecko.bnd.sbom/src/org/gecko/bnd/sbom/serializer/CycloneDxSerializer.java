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

import org.gecko.bnd.sbom.SbomConfig;
import org.gecko.bnd.sbom.model.SbomComponent;
import org.gecko.bnd.sbom.model.SbomLicense;
import org.gecko.bnd.sbom.model.SbomModel;
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

	private static final String		SPEC_VERSION	= "1.6";
	private static final JSONCodec	CODEC			= new JSONCodec();

	@Override
	public String fileExtension() {
		return ".cdx.json";
	}

	@Override
	public Resource serialize(SbomModel model, SbomConfig config) throws Exception {
		Map<String, Object> bom = new LinkedHashMap<>();
		bom.put("bomFormat", "CycloneDX");
		bom.put("specVersion", SPEC_VERSION);
		bom.put("version", 1);
		bom.put("metadata", metadata(model, config));

		List<Object> components = new ArrayList<>();
		for (SbomComponent component : model.getComponents()) {
			components.add(component(component));
		}
		bom.put("components", components);

		// A2.5/Q4: completeness + declared "known unknowns".
		bom.put("compositions", compositions(model));

		String json = CODEC.enc()
			.indent("  ")
			.put(bom)
			.toString();

		return new EmbeddedResource(json, config.created()
			.toEpochMilli());
	}

	private Map<String, Object> metadata(SbomModel model, SbomConfig config) {
		Map<String, Object> metadata = new LinkedHashMap<>();
		metadata.put("timestamp", config.created()
			.toString());

		Map<String, Object> tool = new LinkedHashMap<>();
		tool.put("type", "application");
		tool.put("name", "bnd SBOM Exporter");
		Map<String, Object> tools = new LinkedHashMap<>();
		tools.put("components", listOf(tool));
		metadata.put("tools", tools);

		Map<String, Object> app = new LinkedHashMap<>();
		app.put("type", "application");
		app.put("name", model.getApplicationName());
		metadata.put("component", app);
		return metadata;
	}

	private Map<String, Object> component(SbomComponent component) {
		Map<String, Object> node = new LinkedHashMap<>();
		node.put("type", "library");
		node.put("name", component.getBsn());
		putIfPresent(node, "version", component.getVersion());
		putIfPresent(node, "purl", component.getPurl());

		if (component.getSha512() != null) {
			Map<String, Object> hash = new LinkedHashMap<>();
			hash.put("alg", "SHA-512");
			hash.put("content", component.getSha512());
			node.put("hashes", listOf(hash));
		}
		// CycloneDX distinguishes a validated SPDX id (license.id) from free text (license.name);
		// a component may carry several license entries.
		if (!component.getLicenses()
			.isEmpty()) {
			List<Object> licenses = new ArrayList<>();
			for (SbomLicense license : component.getLicenses()) {
				Map<String, Object> value = license.isSpdx() ? singletonMap("id", license.spdxId())
					: singletonMap("name", license.name());
				licenses.add(singletonMap("license", value));
			}
			node.put("licenses", licenses);
		}
		putIfPresent(node, "publisher", component.getSupplier());

		// Q3.b: flag an unresolvable identity honestly instead of inventing a PURL.
		if (component.isUnverifiedIdentity()) {
			node.put("properties", listOf(property("osgi:identity:matchability", "unverified")));
		}
		// TODO(includeOSGIMetadata): Import-Package ranges / Require-Capability as namespaced
		//   properties; package/class provenance format-natively via CycloneDX `pedigree`.
		return node;
	}

	private List<Object> compositions(SbomModel model) {
		Map<String, Object> composition = new LinkedHashMap<>();
		composition.put("aggregate", model.isDependenciesComplete() ? "complete" : "incomplete");
		if (!model.getKnownUnknowns()
			.isEmpty()) {
			List<Object> notes = new ArrayList<>();
			for (String unknown : model.getKnownUnknowns()) {
				notes.add(property("osgi:known-unknown", unknown));
			}
			composition.put("properties", notes);
		}
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
