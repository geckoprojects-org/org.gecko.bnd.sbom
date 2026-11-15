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
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import aQute.bnd.header.Attrs;
import aQute.bnd.header.Parameters;
import aQute.bnd.osgi.Processor;

/**
 * Which update step is allowed for which library.
 * <p>
 * Default: {@link Scope#MICRO} — only bug-fix releases of the same major.minor line, the ones
 * most likely to be compatible. A larger scope is configured explicitly, for all libraries or
 * per library; major updates are never proposed unless configured. In a bnd workspace the
 * policy comes from the {@value #INSTRUCTION} instruction:
 *
 * <pre>
 * -update-policy: \
 *     default;scope=micro,\
 *     com.fasterxml.jackson.core:*;scope=minor,\
 *     org.bouncycastle:bcprov-jdk18on;scope=minor
 * </pre>
 *
 * Entries are {@code groupId:artifactId} patterns ({@code *} matches anything); the first
 * matching entry wins, {@code default} applies when none matches.
 * <p>
 * {@code buildtime;scope=minor} sets the scope for libraries that are only needed to build or
 * test the workspace — in no application bndrun (see {@link Update.Usage}): JUnit, JaCoCo, bnd
 * itself. They never reach the application, so a larger step is usually safe. Per-library
 * entries still come first; without {@code buildtime}, the default applies to them as well.
 */
public final class VersionPolicy {

	/** Workspace instruction holding the policy. */
	public static final String	INSTRUCTION	= "-update-policy";
	static final String			DEFAULT		= "default";
	static final String			BUILDTIME	= "buildtime";
	static final String			SCOPE		= "scope";

	private record Rule(Pattern pattern, Scope scope) {}

	private final Scope			defaultScope;
	private final Scope			buildtimeScope;
	private final List<Rule>	rules;

	private VersionPolicy(Scope defaultScope, Scope buildtimeScope, List<Rule> rules) {
		this.defaultScope = defaultScope;
		this.buildtimeScope = buildtimeScope;
		this.rules = List.copyOf(rules);
	}

	/** Micro updates for every library. */
	public static VersionPolicy defaults() {
		return new VersionPolicy(Scope.MICRO, null, List.of());
	}

	/** One scope for every library. */
	public static VersionPolicy of(Scope scope) {
		return new VersionPolicy(scope, null, List.of());
	}

	/** The policy of a workspace ({@value #INSTRUCTION}), or the defaults without one. */
	public static VersionPolicy from(Processor workspace) {
		return parse(workspace.getProperty(INSTRUCTION));
	}

	/**
	 * @param instruction the value of {@value #INSTRUCTION}, may be {@code null}
	 * @throws IllegalArgumentException for an unknown scope or an entry without one
	 */
	public static VersionPolicy parse(String instruction) {
		if (instruction == null || instruction.isBlank()) {
			return defaults();
		}
		Scope defaultScope = Scope.MICRO;
		Scope buildtimeScope = null;
		List<Rule> rules = new ArrayList<>();
		for (Map.Entry<String, Attrs> entry : new Parameters(instruction).entrySet()) {
			String key = Processor.removeDuplicateMarker(entry.getKey())
				.trim();
			String value = entry.getValue()
				.get(SCOPE);
			if (value == null) {
				throw new IllegalArgumentException("Entry '" + key + "' of " + INSTRUCTION + " has no scope");
			}
			Scope scope = Scope.parse(value);
			if (DEFAULT.equals(key)) {
				defaultScope = scope;
			} else if (BUILDTIME.equals(key)) {
				buildtimeScope = scope;
			} else {
				rules.add(new Rule(glob(key), scope));
			}
		}
		return new VersionPolicy(defaultScope, buildtimeScope, rules);
	}

	/** Overrides the default scope, keeping the per-library rules and the build-time scope. */
	public VersionPolicy withDefault(Scope scope) {
		return new VersionPolicy(scope, buildtimeScope, rules);
	}

	/** The scope allowed for a library, whatever its usage. */
	public Scope scopeFor(String groupId, String artifactId) {
		return scopeFor(groupId, artifactId, Update.Usage.UNKNOWN);
	}

	/**
	 * The scope allowed for a library: the first matching per-library entry; for a build-time
	 * library then {@code buildtime}, if set; otherwise {@code default}.
	 */
	public Scope scopeFor(String groupId, String artifactId, Update.Usage usage) {
		String ga = groupId + ":" + artifactId;
		for (Rule rule : rules) {
			if (rule.pattern()
				.matcher(ga)
				.matches()) {
				return rule.scope();
			}
		}
		if (usage == Update.Usage.BUILD_TIME && buildtimeScope != null) {
			return buildtimeScope;
		}
		return defaultScope;
	}

	/** The scope for build-time libraries, or {@code null} when the default applies to them. */
	public Scope buildtimeScope() {
		return buildtimeScope;
	}

	public Scope defaultScope() {
		return defaultScope;
	}

	private static Pattern glob(String pattern) {
		StringBuilder regex = new StringBuilder();
		for (char c : pattern.toCharArray()) {
			if (c == '*') {
				regex.append("[^:]*");
			} else {
				regex.append(Pattern.quote(String.valueOf(c)));
			}
		}
		return Pattern.compile(regex.toString());
	}
}
