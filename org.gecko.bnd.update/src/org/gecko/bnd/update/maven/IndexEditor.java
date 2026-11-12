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
package org.gecko.bnd.update.maven;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import aQute.maven.api.Archive;

/**
 * Changes the version of a library in a {@code MavenBndRepository} text index ({@code .mvn}),
 * in place.
 * <p>
 * Only the version field of the matching lines is replaced; order, comments and every other line
 * stay as they are, so the change is a one-line diff. Lines whose version is a macro
 * ({@code ${bndversion}}) are left alone: the macro is the deliberate source of that version.
 * bnd's own index update would remove the line and append a new one at the end, and replace a
 * macro with its value.
 */
public final class IndexEditor {

	/**
	 * @param replaced lines changed
	 * @param macro matching lines left alone because their version is a macro
	 */
	public record Result(int replaced, int macro) {}

	private IndexEditor() {}

	/**
	 * Replaces {@code groupId:artifactId[...]:from} with version {@code to} in every matching line
	 * (all extensions and classifiers of that version).
	 */
	public static Result replace(File index, String groupId, String artifactId, String from, String to)
		throws Exception {
		List<String> lines = Files.readAllLines(index.toPath(), StandardCharsets.UTF_8);
		List<String> result = new ArrayList<>(lines.size());
		int replaced = 0;
		int macro = 0;
		for (String line : lines) {
			String gav = gav(line);
			if (gav == null) {
				result.add(line);
				continue;
			}
			if (gav.contains("${")) {
				String prefix = groupId + ":" + artifactId + ":";
				if (gav.startsWith(prefix)) {
					macro++;
				}
				result.add(line);
				continue;
			}
			Archive archive = Archive.valueOf(gav);
			if (archive != null && archive.revision.group.equals(groupId) && archive.revision.artifact.equals(artifactId)
				&& archive.revision.version.toString()
					.equals(from)
				&& gav.endsWith(":" + from)) {
				int at = line.indexOf(gav);
				String updated = gav.substring(0, gav.length() - from.length()) + to;
				result.add(line.substring(0, at) + updated + line.substring(at + gav.length()));
				replaced++;
			} else {
				result.add(line);
			}
		}
		if (replaced > 0) {
			Files.write(index.toPath(), result, StandardCharsets.UTF_8);
		}
		return new Result(replaced, macro);
	}

	/** The GAV of an index line without comment, or {@code null} for blank and comment lines. */
	static String gav(String line) {
		String s = line.strip();
		if (s.isEmpty() || s.startsWith("#")) {
			return null;
		}
		int comment = s.indexOf('#');
		if (comment > 0) {
			s = s.substring(0, comment)
				.strip();
		}
		return s;
	}
}
