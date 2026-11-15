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
import java.util.regex.Pattern;

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
		if (candidate.compareTo(installed) <= 0 || !successor(installed, candidate)) {
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
	 * {@code true} if {@code candidate} continues the line of {@code installed}: the
	 * {@linkplain #sameFlavor same variant} and the {@linkplain #sameScheme same version scheme}.
	 * Only such a version is an update, whatever its scope; how far it may move is the scope's
	 * business.
	 */
	public static boolean successor(MavenVersion installed, MavenVersion candidate) {
		return sameFlavor(installed, candidate) && sameScheme(installed, candidate);
	}

	/**
	 * Some libraries publish variants of one release, told apart by a suffix: guava
	 * {@code 33.5.0-jre} and {@code 33.5.0-android}, byte-buddy {@code 1.18.17} and
	 * {@code 1.18.17-jdk5}. An update keeps the variant: a version with a suffix that starts with
	 * a letter only moves to versions with the same suffix, a version without one only to
	 * versions without one. Pre-release markers ({@code -rc1}, {@code -beta}, {@code -SNAPSHOT})
	 * are not a variant: {@code 2.0.0-rc1} moves on to {@code 2.0.0}.
	 */
	public static boolean sameFlavor(MavenVersion installed, MavenVersion candidate) {
		return flavor(installed.toString()).equals(flavor(candidate.toString()));
	}

	private static String flavor(String version) {
		if (isPreRelease(version)) {
			return "";
		}
		int dash = version.lastIndexOf('-');
		if (dash < 0 || dash == version.length() - 1) {
			return "";
		}
		String suffix = version.substring(dash + 1)
			.toLowerCase(Locale.ROOT);
		return Character.isLetter(suffix.charAt(0)) ? suffix : "";
	}

	/**
	 * Some libraries once used a date as version, which compares higher than every later
	 * release: commons-collections {@code 20040616} is not newer than {@code 3.2.2}. An update
	 * keeps the scheme: a version whose major is a date ({@code yyyyMMdd}, eight digits or more)
	 * only moves to such versions, any other only to versions that are not.
	 */
	public static boolean sameScheme(MavenVersion installed, MavenVersion candidate) {
		return isDate(installed) == isDate(candidate);
	}

	private static boolean isDate(MavenVersion version) {
		return version.getOSGiVersion()
			.getMajor() >= DATE_MAJOR;
	}

	/** the smallest eight-digit number: a major from here on is a date, not a release line */
	private static final int		DATE_MAJOR	= 10_000_000;

	private static final Pattern	PRE_RELEASE	= Pattern
		.compile(".*[-.](alpha|beta|rc|cr|m|milestone|preview|pre)[-.]?\\d*([-.].*)?$");

	/** -SNAPSHOT, -rc1, -beta12, -alpha, -M3: a pre-release, not a release. */
	public static boolean isPreRelease(String version) {
		String text = version.toLowerCase(Locale.ROOT);
		return text.endsWith("-snapshot") || PRE_RELEASE.matcher(text)
			.matches();
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
