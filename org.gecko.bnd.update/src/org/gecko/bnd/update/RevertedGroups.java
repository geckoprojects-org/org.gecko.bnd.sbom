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

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import org.osgi.resource.Capability;
import org.osgi.resource.Resource;

/**
 * Finds the {@link RevertedGroup groups} among updates reverted one by one: two reverted updates
 * A and B belong together if
 * <ul>
 * <li>B's installed version is the bundle whose requirement failed A (it pins A's library to the
 * old range: {@code org.objectweb.asm.tree 9.9.1 -> osgi.wiring.package: org.objectweb.asm;
 * version=[9.9.1,9.10.0)}), or</li>
 * <li>A failed on a package, bundle or capability that B's library provides — only in a newer
 * version than the installed one ({@code spifly 1.3.8 -> osgi.wiring.package:
 * org.objectweb.asm; version=[9.10.0,10.0.0)}).</li>
 * </ul>
 * Updates whose failure has a known other cause (a {@code -runfw}/{@code -runpath} pin that
 * matches nothing) are left out.
 */
final class RevertedGroups {

	private RevertedGroups() {}

	/**
	 * What the repositories know about the installed version of a library.
	 *
	 * @param identity the bundle as the resolver names it: {@code bsn version}
	 * @param provides its capabilities as {@code namespace:name}, without version
	 */
	record Installed(String identity, Set<String> provides) {}

	/**
	 * One unresolved requirement, parsed from {@code who -> namespace: name; version=…}.
	 *
	 * @param who {@code bsn version} of the requiring bundle, or {@code -runrequires}
	 */
	record Blame(String who, String namespace, String name) {

		static Blame parse(String unresolved) {
			int arrow = unresolved.indexOf(" -> ");
			if (arrow < 0) {
				return null;
			}
			String who = unresolved.substring(0, arrow)
				.trim();
			String rest = unresolved.substring(arrow + 4);
			int colon = rest.indexOf(": ");
			if (colon < 0) {
				return new Blame(who, rest.trim(), null);
			}
			String namespace = rest.substring(0, colon)
				.trim();
			String filter = rest.substring(colon + 2);
			int semicolon = filter.indexOf(';');
			String name = (semicolon < 0 ? filter : filter.substring(0, semicolon)).trim();
			return new Blame(who, namespace, name.isEmpty() ? null : name);
		}
	}

	/**
	 * @param reverted the reverted updates, in the order they were tried
	 * @param unresolved per reverted update: the unresolved requirements of its failure; an update
	 *            without entry (or with a known other cause) is not grouped
	 * @param installed per update: its installed version as the repositories know it; may lack
	 *            updates the repositories do not resolve to a bundle
	 * @return the groups of two or more updates, in the order of their first update
	 */
	static List<RevertedGroup> of(List<Update> reverted, Map<Update, List<String>> unresolved,
		Map<Update, Installed> installed) {
		List<Update> candidates = reverted.stream()
			.filter(unresolved::containsKey)
			.toList();
		int n = candidates.size();
		int[] parent = new int[n];
		for (int i = 0; i < n; i++) {
			parent[i] = i;
		}
		for (int a = 0; a < n; a++) {
			List<Blame> blames = unresolved.get(candidates.get(a))
				.stream()
				.map(Blame::parse)
				.filter(b -> b != null)
				.toList();
			for (int b = 0; b < n; b++) {
				if (a != b && blames(blames, installed.get(candidates.get(b)))) {
					union(parent, a, b);
				}
			}
		}
		Map<Integer, List<Update>> components = new TreeMap<>();
		for (int i = 0; i < n; i++) {
			components.computeIfAbsent(find(parent, i), k -> new ArrayList<>())
				.add(candidates.get(i));
		}
		List<RevertedGroup> groups = new ArrayList<>();
		for (List<Update> component : components.values()) {
			if (component.size() > 1) {
				groups.add(new RevertedGroup(component));
			}
		}
		return groups;
	}

	/** {@code true} if one of A's failed requirements points at B's installed bundle. */
	private static boolean blames(List<Blame> blames, Installed other) {
		if (other == null) {
			return false;
		}
		for (Blame blame : blames) {
			if (blame.who()
				.equals(other.identity())) {
				return true;
			}
			if (blame.name() != null && other.provides()
				.contains(blame.namespace() + ":" + blame.name())) {
				return true;
			}
		}
		return false;
	}

	/** The installed version of each update's library among the repositories' resources. */
	static Map<Update, Installed> installed(Collection<Update> updates, Collection<Resource> resources) {
		Map<Update, Installed> result = new LinkedHashMap<>();
		for (Update update : updates) {
			Bundles.Bundle bundle = Bundles.of(update.library(), resources);
			if (bundle != null) {
				result.put(update, installed(bundle));
			}
		}
		return result;
	}

	static Installed installed(Bundles.Bundle bundle) {
		Set<String> provides = new HashSet<>();
		for (Capability capability : bundle.resource()
			.getCapabilities(null)) {
			Object name = capability.getAttributes()
				.get(capability.getNamespace());
			if (name != null) {
				provides.add(capability.getNamespace() + ":" + name);
			}
		}
		return new Installed(bundle.identity(), provides);
	}

	private static int find(int[] parent, int i) {
		while (parent[i] != i) {
			parent[i] = parent[parent[i]];
			i = parent[i];
		}
		return i;
	}

	private static void union(int[] parent, int a, int b) {
		int ra = find(parent, a);
		int rb = find(parent, b);
		if (ra != rb) {
			// the smaller index is the root: groups keep the order of their first update
			parent[Math.max(ra, rb)] = Math.min(ra, rb);
		}
	}
}
