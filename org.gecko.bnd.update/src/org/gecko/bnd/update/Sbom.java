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

import java.io.InputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import aQute.lib.io.IO;
import aQute.lib.json.JSONCodec;

/**
 * The parts of a CycloneDX SBOM written by the bnd SBOM exporter that a check needs: which
 * libraries the application contains and where each one sits ({@code osgi:layer},
 * {@code osgi:embedded:in}, {@code osgi:embedded:source}, {@code osgi:repository:name}).
 */
public final class Sbom {

	private final String						application;
	private final Map<String, List<Location>>	locations;

	private Sbom(String application, Map<String, List<Location>> locations) {
		this.application = application;
		this.locations = locations;
	}

	/** Reads a CycloneDX JSON SBOM. */
	@SuppressWarnings("unchecked")
	public static Sbom read(InputStream in) throws Exception {
		Map<String, Object> bom = new JSONCodec().dec()
			.from(IO.collect(in))
			.get(Map.class);
		Map<String, Object> metadata = map(bom.get("metadata"));
		String application = string(map(metadata.get("component")).get("name"));

		List<Map<String, Object>> components = new ArrayList<>();
		Object list = bom.get("components");
		if (list instanceof List<?> l) {
			l.forEach(c -> components.add(map(c)));
		}
		Map<String, String> nameByRef = new HashMap<>();
		for (Map<String, Object> component : components) {
			nameByRef.put(string(component.get("bom-ref")), string(component.get("name")));
		}

		Map<String, List<Location>> locations = new LinkedHashMap<>();
		for (Map<String, Object> component : components) {
			String purl = string(component.get("purl"));
			if (purl == null) {
				continue;
			}
			Map<String, String> properties = new HashMap<>();
			Object props = component.get("properties");
			if (props instanceof List<?> l) {
				for (Object p : l) {
					Map<String, Object> property = map(p);
					properties.put(string(property.get("name")), string(property.get("value")));
				}
			}
			String embeddedIn = properties.get("osgi:embedded:in");
			Location location = embeddedIn != null
				? new Location(Location.EMBEDDED, nameByRef.getOrDefault(embeddedIn, embeddedIn),
					properties.get("osgi:embedded:source"), null)
				: new Location(properties.get("osgi:layer"), null, null, properties.get("osgi:repository:name"));
			locations.computeIfAbsent(ga(purl), k -> new ArrayList<>())
				.add(location);
		}
		return new Sbom(application, locations);
	}

	public String application() {
		return application;
	}

	/** Where the library {@code groupId:artifactId} sits; empty if the SBOM does not list it. */
	public List<Location> locations(String groupId, String artifactId) {
		return locations.getOrDefault(groupId + ":" + artifactId, List.of());
	}

	/** {@code pkg:maven/group/artifact@version?...} → {@code group:artifact}, percent-decoded */
	static String ga(String purl) {
		String rest = purl.startsWith("pkg:maven/") ? purl.substring("pkg:maven/".length()) : purl;
		int at = rest.indexOf('@');
		if (at >= 0) {
			rest = rest.substring(0, at);
		}
		return URLDecoder.decode(rest.replace('/', ':'), StandardCharsets.UTF_8);
	}

	@SuppressWarnings("unchecked")
	private static Map<String, Object> map(Object value) {
		return value instanceof Map<?, ?> m ? (Map<String, Object>) m : Map.of();
	}

	private static String string(Object value) {
		return value != null ? value.toString() : null;
	}
}
