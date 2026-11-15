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

import java.io.File;
import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.util.List;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The bnd version a workspace is built with — its most important build-time dependency, but in
 * no {@code .mvn} index: it is set where the build tool reads it.
 * <ul>
 * <li>Gradle: {@code bnd_version} (or {@code bndVersion}) in {@code gradle.properties}, or a
 * literal version of the {@code biz.aQute.bnd.*} plugin in {@code settings.gradle};</li>
 * <li>Maven: the {@code bnd.version} property in {@code pom.xml}.</li>
 * </ul>
 * Reported as a build-time update ({@link IndexOrigin.Kind#TOOLCHAIN}); never changed by
 * {@code apply}.
 *
 * @param version the bnd version, e.g. {@code 7.4.0}
 * @param source where it is set, e.g. {@code gradle.properties bnd_version}
 */
public record Toolchain(String version, String source) {

	/** The artifact whose versions stand for bnd's releases. */
	public static final Library	BND				= new Library("biz.aQute.bnd", "biz.aQute.bndlib", "");

	private static final List<String>	PROPERTIES		= List.of("bnd_version", "bndVersion");
	private static final Pattern		SETTINGS_PLUGIN	= Pattern
		.compile("id\\s*\\(?\\s*['\"]biz\\.aQute\\.bnd(?:\\.[\\w.]+)?['\"]\\s*\\)?\\s*version\\s*\\(?\\s*['\"]([0-9][^'\"]*)['\"]");
	private static final Pattern		POM_PROPERTY	= Pattern.compile("<bnd\\.version>\\s*([^<\\s]+)\\s*</bnd\\.version>");

	/** The bnd version of the workspace in {@code dir}, or {@code null} if none is found. */
	public static Toolchain detect(File dir) {
		if (dir == null) {
			return null;
		}
		try {
			File properties = new File(dir, "gradle.properties");
			if (properties.isFile()) {
				Properties p = new Properties();
				try (Reader reader = Files.newBufferedReader(properties.toPath())) {
					p.load(reader);
				}
				for (String key : PROPERTIES) {
					String value = p.getProperty(key);
					if (value != null && !value.isBlank() && !value.contains("$")) {
						return new Toolchain(value.trim(), "gradle.properties " + key);
					}
				}
			}
			for (String name : List.of("settings.gradle", "settings.gradle.kts")) {
				Toolchain found = find(new File(dir, name), SETTINGS_PLUGIN, name);
				if (found != null) {
					return found;
				}
			}
			return find(new File(dir, "pom.xml"), POM_PROPERTY, "pom.xml bnd.version");
		} catch (IOException e) {
			return null;
		}
	}

	private static Toolchain find(File file, Pattern pattern, String source) throws IOException {
		if (!file.isFile()) {
			return null;
		}
		Matcher matcher = pattern.matcher(Files.readString(file.toPath()));
		return matcher.find() ? new Toolchain(matcher.group(1), source) : null;
	}

	/** The toolchain as a library at its version. */
	public Library library() {
		return new Library(BND.groupId(), BND.artifactId(), version);
	}
}
