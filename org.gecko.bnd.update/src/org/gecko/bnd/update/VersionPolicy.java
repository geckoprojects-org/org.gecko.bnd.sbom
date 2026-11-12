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
 */
public final class VersionPolicy {

	/** Workspace instruction holding the policy. */
	public static final String	INSTRUCTION	= "-update-policy";
	static final String			DEFAULT		= "default";
	static final String			SCOPE		= "scope";

	private record Rule(Pattern pattern, Scope scope) {}

	private final Scope			defaultScope;
	private final List<Rule>	rules;

	private VersionPolicy(Scope defaultScope, List<Rule> rules) {
		this.defaultScope = defaultScope;
		this.rules = List.copyOf(rules);
	}

	/** Micro updates for every library. */
	public static VersionPolicy defaults() {
		return new VersionPolicy(Scope.MICRO, List.of());
	}

	/** One scope for every library. */
	public static VersionPolicy of(Scope scope) {
		return new VersionPolicy(scope, List.of());
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
			} else {
				rules.add(new Rule(glob(key), scope));
			}
		}
		return new VersionPolicy(defaultScope, rules);
	}

	/** Overrides the default scope, keeping the per-library rules. */
	public VersionPolicy withDefault(Scope scope) {
		return new VersionPolicy(scope, rules);
	}

	/** The scope allowed for a library. */
	public Scope scopeFor(String groupId, String artifactId) {
		String ga = groupId + ":" + artifactId;
		for (Rule rule : rules) {
			if (rule.pattern()
				.matcher(ga)
				.matches()) {
				return rule.scope();
			}
		}
		return defaultScope;
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
