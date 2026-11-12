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
package org.gecko.bnd.update.cli;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

public class MainTest {

	private final ByteArrayOutputStream	out		= new ByteArrayOutputStream();
	private final ByteArrayOutputStream	err		= new ByteArrayOutputStream();
	private final Main					main	= new Main(new PrintStream(out, true, StandardCharsets.UTF_8),
		new PrintStream(err, true, StandardCharsets.UTF_8));

	@Test
	public void options() {
		assertThat(Main.options(new String[] {
			"vulnerabilities", "--trivy", "t.json", "--against-updates", "--scope", "minor"
		})).containsEntry("trivy", "t.json")
			.containsEntry("against-updates", "true")
			.containsEntry("scope", "minor");
		assertThatIllegalArgumentException().isThrownBy(() -> Main.options(new String[] {
			"updates", "--nope", "x"
		}));
		assertThatIllegalArgumentException().isThrownBy(() -> Main.options(new String[] {
			"updates", "--scope"
		}));
	}

	@Test
	public void usageErrors() {
		assertThat(main.run(new String[0])).isEqualTo(Main.USAGE);
		assertThat(main.run(new String[] {
			"frobnicate"
		})).isEqualTo(Main.USAGE);
		assertThat(main.run(new String[] {
			"vulnerabilities", "--workspace", "."
		})).isEqualTo(Main.USAGE);
		assertThat(main.run(new String[] {
			"updates", "--workspace", "/nonexistent"
		})).isEqualTo(Main.USAGE);
		assertThat(err.toString(StandardCharsets.UTF_8)).contains("Usage:")
			.contains("Not a bnd workspace");
	}

	@Test
	public void help() {
		assertThat(main.run(new String[] {
			"--help"
		})).isEqualTo(Main.OK);
		assertThat(err.toString(StandardCharsets.UTF_8)).contains("bnd-update updates");
	}
}
