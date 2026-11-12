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
package org.gecko.bnd.update.report;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.gecko.bnd.update.CheckReport;
import org.gecko.bnd.update.Location;
import org.gecko.bnd.update.Proposal;
import org.gecko.bnd.update.Update;
import org.gecko.bnd.update.Vulnerability;

import aQute.bnd.version.MavenVersion;
import aQute.lib.json.JSONCodec;

/**
 * Neutral renderings of the results: JSON for machines, Markdown for people (a CI step summary,
 * a PR or MR description, an issue).
 */
public final class Reports {

	private static final JSONCodec CODEC = new JSONCodec();

	private Reports() {}

	// ---- function 1: updates

	public static String json(List<Update> updates) throws Exception {
		List<Object> list = new ArrayList<>();
		for (Update update : updates) {
			Map<String, Object> node = new LinkedHashMap<>();
			node.put("library", update.library()
				.ga());
			node.put("installed", update.library()
				.version());
			node.put("repository", update.repository());
			node.put("index", update.index());
			node.put("allowedScope", update.allowed()
				.id());
			node.put("proposed", string(update.proposed()));
			node.put("latest", string(update.latest()));
			node.put("latestScope", update.latestScope()
				.id());
			node.put("available", update.available()
				.stream()
				.map(MavenVersion::toString)
				.toList());
			list.add(node);
		}
		return encode(list);
	}

	public static String markdown(List<Update> updates) {
		StringBuilder md = new StringBuilder("## Updates\n\n");
		List<Update> proposed = updates.stream()
			.filter(Update::isProposed)
			.toList();
		if (proposed.isEmpty()) {
			md.append("No update within the version policy.\n");
		} else {
			md.append("| Library | Installed | Proposed | Allowed | Latest | Repository |\n|---|---|---|---|---|---|\n");
			for (Update u : proposed) {
				md.append("| `")
					.append(u.library()
						.ga())
					.append("` | ")
					.append(u.library()
						.version())
					.append(" | **")
					.append(u.proposed())
					.append("** | ")
					.append(u.allowed()
						.id())
					.append(" | ")
					.append(u.latest())
					.append(" (")
					.append(u.latestScope()
						.id())
					.append(") | ")
					.append(u.repository())
					.append(" |\n");
			}
		}
		List<Update> outside = updates.stream()
			.filter(u -> !u.isProposed())
			.toList();
		if (!outside.isEmpty()) {
			md.append("\n### Outside the version policy\n\n");
			for (Update u : outside) {
				md.append("- `")
					.append(u.library())
					.append("` → ")
					.append(u.latest())
					.append(" needs a ")
					.append(u.latestScope()
						.id())
					.append(" update (allowed: ")
					.append(u.allowed()
						.id())
					.append(")\n");
			}
		}
		return md.toString();
	}

	// ---- function 2: vulnerabilities

	public static String json(CheckReport report) throws Exception {
		List<Object> list = new ArrayList<>();
		for (Proposal p : report.proposals()) {
			Map<String, Object> node = new LinkedHashMap<>();
			node.put("library", p.library()
				.ga());
			node.put("installed", p.library()
				.version());
			node.put("status", p.status()
				.name());
			node.put("allowedScope", p.allowed()
				.id());
			node.put("proposed", string(p.proposed()));
			node.put("neededScope", p.needed() != null ? p.needed()
				.id() : null);
			List<Object> vulnerabilities = new ArrayList<>();
			for (Vulnerability v : p.vulnerabilities()) {
				Map<String, Object> vn = new LinkedHashMap<>();
				vn.put("id", v.id());
				vn.put("severity", v.severity());
				vn.put("fixedVersions", v.fixedVersions());
				vn.put("title", v.title());
				vulnerabilities.add(vn);
			}
			node.put("vulnerabilities", vulnerabilities);
			List<Object> locations = new ArrayList<>();
			for (Location l : p.locations()) {
				Map<String, Object> ln = new LinkedHashMap<>();
				ln.put("layer", l.layer());
				ln.put("bundle", l.bundle());
				ln.put("source", l.source());
				ln.put("repository", l.repository());
				locations.add(ln);
			}
			node.put("locations", locations);
			list.add(node);
		}
		Map<String, Object> root = new LinkedHashMap<>();
		root.put("application", report.application());
		root.put("proposals", list);
		return encode(root);
	}

	public static String markdown(CheckReport report) {
		StringBuilder md = new StringBuilder("## Vulnerabilities")
			.append(report.application() != null ? " — " + report.application() : "")
			.append("\n\n");
		if (report.proposals()
			.isEmpty()) {
			return md.append("No vulnerable library.\n")
				.toString();
		}
		md.append("| Library | Installed | Vulnerabilities | Fix | Where |\n|---|---|---|---|---|\n");
		for (Proposal p : report.proposals()) {
			md.append("| `")
				.append(p.library()
					.ga())
				.append("` | ")
				.append(p.library()
					.version())
				.append(" | ")
				.append(p.vulnerabilities()
					.size())
				.append(" (")
				.append(p.vulnerabilities()
					.stream()
					.map(Vulnerability::severity)
					.distinct()
					.collect(Collectors.joining(", ")))
				.append(") | ")
				.append(fix(p))
				.append(" | ")
				.append(p.locations()
					.stream()
					.map(Reports::where)
					.distinct()
					.collect(Collectors.joining("<br>")))
				.append(" |\n");
		}
		return md.toString();
	}

	private static String fix(Proposal p) {
		return switch (p.status()) {
			case UPDATE -> "**" + p.proposed() + "** (" + p.allowed()
				.id() + ")";
			case OUTSIDE_POLICY -> "needs a " + p.needed()
				.id() + " update (allowed: " + p.allowed()
					.id() + ")";
			case NO_FIX -> "no available version fixes all";
		};
	}

	private static String where(Location l) {
		if (l.isEmbedded()) {
			return "embedded in `" + l.bundle() + "`" + (l.source() != null ? " (" + l.source() + ")" : "");
		}
		return (l.layer() != null ? l.layer() : "component") + (l.repository() != null ? ", " + l.repository() : "");
	}

	private static String string(Object value) {
		return value != null ? value.toString() : null;
	}

	private static String encode(Object value) throws Exception {
		return CODEC.enc()
			.indent("  ")
			.put(value)
			.toString();
	}
}
