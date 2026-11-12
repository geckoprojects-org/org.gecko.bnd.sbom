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

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class IndexEditorTest {

	@TempDir
	Path dir;

	@Test
	public void replacesInPlaceAndKeepsEverythingElse() throws Exception {
		Path index = dir.resolve("central.mvn");
		Files.writeString(index, """
			# bnd itself
			biz.aQute.bnd:biz.aQute.bndlib:${bndversion}

			org.slf4j:slf4j-api:2.0.17
			org.slf4j:slf4j-api:jar:sources:2.0.17  # sources too
			org.slf4j:slf4j-simple:2.0.17
			com.example:other:2.0.17
			""", StandardCharsets.UTF_8);

		IndexEditor.Result result = IndexEditor.replace(index.toFile(), "org.slf4j", "slf4j-api", "2.0.17", "2.0.20");

		assertThat(result.replaced()).isEqualTo(2);
		assertThat(Files.readString(index)).isEqualTo("""
			# bnd itself
			biz.aQute.bnd:biz.aQute.bndlib:${bndversion}

			org.slf4j:slf4j-api:2.0.20
			org.slf4j:slf4j-api:jar:sources:2.0.20  # sources too
			org.slf4j:slf4j-simple:2.0.17
			com.example:other:2.0.17
			""");
	}

	@Test
	public void macroVersionsAreLeftAlone() throws Exception {
		Path index = dir.resolve("central.mvn");
		String content = "biz.aQute.bnd:biz.aQute.bndlib:${bndversion}\n";
		Files.writeString(index, content, StandardCharsets.UTF_8);

		IndexEditor.Result result = IndexEditor.replace(index.toFile(), "biz.aQute.bnd", "biz.aQute.bndlib", "7.4.0",
			"7.4.1");

		assertThat(result.replaced()).isZero();
		assertThat(result.macro()).isEqualTo(1);
		assertThat(Files.readString(index)).isEqualTo(content);
	}

	@Test
	public void otherVersionsAreNotTouched() throws Exception {
		Path index = dir.resolve("central.mvn");
		String content = "org.slf4j:slf4j-api:1.7.36\norg.slf4j:slf4j-api:2.0.17\n";
		Files.writeString(index, content, StandardCharsets.UTF_8);

		IndexEditor.replace(index.toFile(), "org.slf4j", "slf4j-api", "2.0.17", "2.0.20");

		assertThat(Files.readString(index)).isEqualTo("org.slf4j:slf4j-api:1.7.36\norg.slf4j:slf4j-api:2.0.20\n");
	}
}
