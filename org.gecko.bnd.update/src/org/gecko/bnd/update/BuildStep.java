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

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Locale;

/**
 * Builds the workspace after updates were applied — whatever build the workspace uses (Gradle,
 * Maven, a script). Kept outside the library so that it stays independent of build tools.
 */
@FunctionalInterface
public interface BuildStep {

	/**
	 * @param ok {@code true} if the build succeeded
	 * @param output the end of the build's output, for the report
	 */
	record Result(boolean ok, String output) {}

	Result build(File workspace) throws Exception;

	/**
	 * Runs a shell command in the workspace directory ({@code sh -c}, on Windows {@code cmd /c}),
	 * e.g. {@code ./gradlew build -x test}; the result keeps the last lines of its output.
	 */
	static BuildStep command(String command) {
		return workspace -> {
			boolean windows = System.getProperty("os.name", "")
				.toLowerCase(Locale.ROOT)
				.contains("win");
			ProcessBuilder builder = windows ? new ProcessBuilder("cmd", "/c", command)
				: new ProcessBuilder("sh", "-c", command);
			builder.directory(workspace)
				.redirectErrorStream(true);
			Process process = builder.start();
			ArrayDeque<String> tail = new ArrayDeque<>();
			try (BufferedReader reader = new BufferedReader(
				new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
				String line;
				while ((line = reader.readLine()) != null) {
					tail.addLast(line);
					if (tail.size() > 40) {
						tail.removeFirst();
					}
				}
			}
			int exit = process.waitFor();
			return new Result(exit == 0, String.join("\n", tail));
		};
	}
}
