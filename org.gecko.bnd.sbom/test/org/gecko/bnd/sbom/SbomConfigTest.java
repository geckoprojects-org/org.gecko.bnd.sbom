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
package org.gecko.bnd.sbom;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.Map;

import org.gecko.bnd.sbom.model.SbomLevel;
import org.gecko.bnd.sbom.model.SbomModel;
import org.gecko.bnd.sbom.serializer.CycloneDxSerializer;
import org.gecko.bnd.sbom.serializer.SbomFormat;
import org.gecko.bnd.sbom.serializer.SpdxSerializer;
import org.junit.jupiter.api.Test;

import aQute.bnd.osgi.Processor;
import aQute.bnd.osgi.Resource;

/**
 * Parsing and validation of the {@code -sbom} instruction and the export options (#18), and the
 * creation time that ends up on the exported file (#19).
 */
public class SbomConfigTest {

	@Test
	public void defaultsWithoutInstruction() {
		Processor reporter = new Processor();
		SbomConfig config = SbomConfig.from(reporter, "", Map.of());

		assertThat(config.level()).isEqualTo(SbomLevel.SIMPLE);
		assertThat(config.format()).isEqualTo(SbomFormat.CYCLONEDX);
		assertThat(config.includeOSGIMetadata()).isFalse();
		assertThat(reporter.isOk()).isTrue();
	}

	@Test
	public void commaSeparatedInstruction() {
		Processor reporter = new Processor();
		SbomConfig config = SbomConfig.from(reporter, "level=medium, format=spdx", Map.of());

		assertThat(config.level()).isEqualTo(SbomLevel.MEDIUM);
		assertThat(config.format()).isEqualTo(SbomFormat.SPDX);
		assertThat(reporter.isOk()).isTrue();
	}

	@Test
	public void semicolonSeparatedInstructionIsAcceptedToo() {
		Processor reporter = new Processor();
		SbomConfig config = SbomConfig.from(reporter, "level=medium;format=spdx", Map.of());

		assertThat(config.level()).isEqualTo(SbomLevel.MEDIUM);
		assertThat(config.format()).isEqualTo(SbomFormat.SPDX);
		assertThat(reporter.isOk()).isTrue();
	}

	@Test
	public void optionsTakePrecedenceOverInstruction() {
		Processor reporter = new Processor();
		SbomConfig config = SbomConfig.from(reporter, "level=medium, format=spdx", Map.of("format", "cyclonedx"));

		assertThat(config.level()).isEqualTo(SbomLevel.MEDIUM);
		assertThat(config.format()).isEqualTo(SbomFormat.CYCLONEDX);
	}

	@Test
	public void invalidValuesAreErrorsNotSilentDefaults() {
		Processor reporter = new Processor();
		SbomConfig.from(reporter, "level=mediun, format=xml, includeOSGIMetadata=yes, timestamp=today", Map.of());

		assertThat(reporter.getErrors()).hasSize(4);
		assertThat(reporter.getErrors()).anyMatch(e -> e.contains("'mediun'") && e.contains("simple, medium, full"));
		assertThat(reporter.getErrors()).anyMatch(e -> e.contains("'xml'") && e.contains("cyclonedx, spdx"));
		assertThat(reporter.getErrors()).anyMatch(e -> e.contains("'yes'"));
		assertThat(reporter.getErrors()).anyMatch(e -> e.contains("'today'"));
	}

	@Test
	public void invalidOptionValueIsAnError() {
		Processor reporter = new Processor();
		SbomConfig.from(reporter, "", Map.of("level", "max"));

		assertThat(reporter.getErrors()).singleElement()
			.asString()
			.contains("'max'");
	}

	@Test
	public void unknownKeyIsAWarning() {
		Processor reporter = new Processor();
		SbomConfig config = SbomConfig.from(reporter, "level=medium, colour=blue", Map.of());

		assertThat(reporter.getErrors()).isEmpty();
		assertThat(reporter.getWarnings()).singleElement()
			.asString()
			.contains("'colour'");
		assertThat(config.level()).isEqualTo(SbomLevel.MEDIUM);
	}

	@Test
	public void malformedInstructionIsAnErrorWithoutException() {
		Processor reporter = new Processor();
		// a forgotten separator: bnd's property parser rejects it with an exception
		SbomConfig.from(reporter, "level=medium format=spdx", Map.of());

		assertThat(reporter.getErrors()).singleElement()
			.asString()
			.contains("-sbom")
			.contains("level=medium, format=spdx");
	}

	@Test
	public void timestampOptionSetsCreationTime() {
		Processor reporter = new Processor();
		SbomConfig config = SbomConfig.from(reporter, "timestamp=2026-01-01T00:00:00Z", Map.of());

		assertThat(config.created()).isEqualTo(Instant.parse("2026-01-01T00:00:00Z"));
	}

	@Test
	public void exportedResourceCarriesCreationTime() throws Exception {
		Instant created = Instant.parse("2026-01-01T00:00:00Z");
		SbomModel model = new SbomModel().setApplicationName("app.bndrun");

		Resource cdx = new CycloneDxSerializer().serialize(model,
			SbomConfig.of(SbomLevel.SIMPLE, SbomFormat.CYCLONEDX, false, created.toString()));
		Resource spdx = new SpdxSerializer().serialize(model,
			SbomConfig.of(SbomLevel.SIMPLE, SbomFormat.SPDX, false, created.toString()));

		assertThat(cdx.lastModified()).isEqualTo(created.toEpochMilli());
		assertThat(spdx.lastModified()).isEqualTo(created.toEpochMilli());
	}

	@Test
	public void withoutTimestampCreationTimeIsNow() throws Exception {
		long before = System.currentTimeMillis();
		Resource cdx = new CycloneDxSerializer().serialize(new SbomModel().setApplicationName("app.bndrun"),
			SbomConfig.of(SbomLevel.SIMPLE, SbomFormat.CYCLONEDX, false, null));

		assertThat(cdx.lastModified()).isBetween(before, System.currentTimeMillis());
	}
}
