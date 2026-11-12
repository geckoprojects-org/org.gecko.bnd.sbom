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

import java.util.Locale;

import aQute.bnd.version.MavenVersion;
import aQute.bnd.version.Version;

/**
 * How far an update may move away from the installed version. Ordered from the smallest to
 * the largest step.
 */
public enum Scope {

	/** same major and minor version: 2.19.2 → 2.19.3 */
	MICRO,
	/** same major version: 2.19.2 → 2.20.1 */
	MINOR,
	/** any higher version: 2.19.2 → 3.0.0 */
	MAJOR;

	/** {@code true} if {@code candidate} is higher than {@code installed} and within this scope. */
	public boolean allows(MavenVersion installed, MavenVersion candidate) {
		if (candidate.compareTo(installed) <= 0 || !sameFlavor(installed, candidate)) {
			return false;
		}
		Version from = installed.getOSGiVersion();
		Version to = candidate.getOSGiVersion();
		return switch (this) {
			case MICRO -> from.getMajor() == to.getMajor() && from.getMinor() == to.getMinor();
			case MINOR -> from.getMajor() == to.getMajor();
			case MAJOR -> true;
		};
	}

	/**
	 * Some libraries publish variants of one release, told apart by a suffix: guava
	 * {@code 33.5.0-jre} and {@code 33.5.0-android}. An update keeps the variant: a version with
	 * a non-numeric suffix only moves to versions with the same suffix, a version without one
	 * only to versions without one.
	 */
	public static boolean sameFlavor(MavenVersion installed, MavenVersion candidate) {
		return flavor(installed.toString()).equals(flavor(candidate.toString()));
	}

	private static String flavor(String version) {
		int dash = version.lastIndexOf('-');
		if (dash < 0) {
			return "";
		}
		String suffix = version.substring(dash + 1)
			.toLowerCase(Locale.ROOT);
		return suffix.chars()
			.allMatch(Character::isLetter) ? suffix : "";
	}

	/** The smallest scope that allows the step from {@code installed} to {@code candidate}. */
	public static Scope of(MavenVersion installed, MavenVersion candidate) {
		for (Scope scope : values()) {
			if (scope.allows(installed, candidate)) {
				return scope;
			}
		}
		return MAJOR;
	}

	/** Lower case name as used in configuration and reports. */
	public String id() {
		return name().toLowerCase(Locale.ROOT);
	}

	/** Parses {@code micro}, {@code minor} or {@code major}, case-insensitive. */
	public static Scope parse(String value) {
		for (Scope scope : values()) {
			if (scope.id()
				.equalsIgnoreCase(value.trim())) {
				return scope;
			}
		}
		throw new IllegalArgumentException("Unknown scope '" + value + "', expected micro, minor or major");
	}
}
