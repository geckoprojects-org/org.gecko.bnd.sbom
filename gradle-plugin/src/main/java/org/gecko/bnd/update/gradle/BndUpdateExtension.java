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
package org.gecko.bnd.update.gradle;

import org.gradle.api.file.ConfigurableFileCollection;
import org.gradle.api.file.DirectoryProperty;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.provider.ListProperty;
import org.gradle.api.provider.Property;

/**
 * Configuration of the bnd update tasks: {@code bndUpdate { ... }} in the root project of a bnd
 * workspace. Every setting is optional; without any, the tasks use the workspace's
 * {@code -update-policy} (micro by default).
 */
public interface BndUpdateExtension {

	/** Default scope for the run: micro, minor or major; unset uses {@code -update-policy}. */
	Property<String> getScope();

	/** bndApply: {@code each} (one by one, keep what passes) or {@code all} (all or nothing). */
	Property<String> getMode();

	/** bndApply: only these libraries, {@code groupId:artifactId} patterns. */
	ListProperty<String> getOnly();

	/** bndApply: build command that verifies each update, e.g. {@code ./gradlew build -x test}. */
	Property<String> getBuildCommand();

	/** bndVulnerabilities, and bndApply when set: the Trivy JSON report. */
	RegularFileProperty getTrivyReport();

	/** The SBOM the Trivy report was made from; adds where each library sits. */
	RegularFileProperty getSbom();

	/** text, json or markdown. */
	Property<String> getFormat();

	/** Where the reports go. */
	DirectoryProperty getOutputDirectory();

	/**
	 * Fail the task when the tool reports something to act on (exit 2: a vulnerability without
	 * a fix within the policy, a bndrun that does not resolve, a reverted update).
	 */
	Property<Boolean> getFailOnFindings();

	/** The bnd-update CLI jar to run; unset resolves {@link #getCliVersion()} from the repositories. */
	ConfigurableFileCollection getCliJar();

	/** Version of org.geckoprojects.bnd:org.gecko.bnd.update.cli. */
	Property<String> getCliVersion();
}
