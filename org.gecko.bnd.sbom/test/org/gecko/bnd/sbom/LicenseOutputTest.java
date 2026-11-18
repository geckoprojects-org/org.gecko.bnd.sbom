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

import java.io.ByteArrayOutputStream;
import java.util.List;
import java.util.Map;

import org.gecko.bnd.sbom.model.SbomComponent;
import org.gecko.bnd.sbom.model.SbomLevel;
import org.gecko.bnd.sbom.model.SbomLicense;
import org.gecko.bnd.sbom.model.SbomModel;
import org.gecko.bnd.sbom.serializer.CycloneDxSerializer;
import org.gecko.bnd.sbom.serializer.SbomFormat;
import org.gecko.bnd.sbom.serializer.SpdxSerializer;
import org.junit.jupiter.api.Test;

import aQute.bnd.osgi.Resource;
import aQute.lib.json.JSONCodec;

/**
 * How ids, expressions and free text end up in CycloneDX and SPDX (#16).
 */
public class LicenseOutputTest {

	private static final JSONCodec CODEC = new JSONCodec();

	private static SbomModel model(SbomLicense... licenses) {
		SbomComponent component = new SbomComponent().setBsn("c")
			.setVersion("1.0.0");
		for (SbomLicense license : licenses) {
			component.addLicense(license);
		}
		return new SbomModel().setApplicationName("app")
			.addComponent(component);
	}

	@Test
	public void cycloneDxSingleExpression() throws Exception {
		assertThat(cdxLicenses(model(SbomLicense.expression("(Apache-2.0 OR EPL-2.0)"))))
			.containsExactly(Map.of("expression", "(Apache-2.0 OR EPL-2.0)", "acknowledgement", "concluded"));
	}

	@Test
	public void cycloneDxIdsAndExpressionBecomeOneExpression() throws Exception {
		assertThat(cdxLicenses(model(SbomLicense.spdx("MIT"),
			SbomLicense.expression("GPL-2.0-only WITH Classpath-exception-2.0"))))
				.containsExactly(Map.of("expression", "MIT AND (GPL-2.0-only WITH Classpath-exception-2.0)",
					"acknowledgement", "concluded"));
	}

	@Test
	public void cycloneDxExpressionNextToFreeTextFallsBackToNames() throws Exception {
		assertThat(cdxLicenses(model(SbomLicense.expression("(Apache-2.0 OR EPL-2.0)"), SbomLicense.named("Vendor"))))
			.containsExactly(Map.of("license", Map.of("name", "(Apache-2.0 OR EPL-2.0)", "acknowledgement", "concluded")),
				Map.of("license", Map.of("name", "Vendor", "acknowledgement", "concluded")));
	}

	@Test
	public void cycloneDxIdsStayLicenseEntries() throws Exception {
		assertThat(cdxLicenses(model(SbomLicense.spdx("EPL-2.0"))))
			.containsExactly(Map.of("license", Map.of("id", "EPL-2.0", "acknowledgement", "concluded")));
	}

	@Test
	@SuppressWarnings("unchecked")
	public void spdxExpressionsGoIntoTheLicenseExpression() throws Exception {
		Map<String, Object> single = decode(new SpdxSerializer().serialize(
			model(SbomLicense.expression("(Apache-2.0 OR EPL-2.0)")), config(SbomFormat.SPDX)));
		Map<String, Object> mixed = decode(new SpdxSerializer().serialize(
			model(SbomLicense.spdx("MIT"), SbomLicense.expression("Apache-2.0 OR EPL-2.0")), config(SbomFormat.SPDX)));

		// package 0 is the application
		assertThat(((List<Map<String, Object>>) single.get("packages")).get(1))
			.containsEntry("licenseDeclared", "(Apache-2.0 OR EPL-2.0)");
		assertThat(((List<Map<String, Object>>) mixed.get("packages")).get(1))
			.containsEntry("licenseDeclared", "MIT AND (Apache-2.0 OR EPL-2.0)");
	}

	@SuppressWarnings("unchecked")
	private static List<Object> cdxLicenses(SbomModel model) throws Exception {
		Map<String, Object> bom = decode(new CycloneDxSerializer().serialize(model, config(SbomFormat.CYCLONEDX)));
		return (List<Object>) ((List<Map<String, Object>>) bom.get("components")).get(0)
			.get("licenses");
	}

	private static SbomConfig config(SbomFormat format) {
		return SbomConfig.of(SbomLevel.MEDIUM, format, false, "2026-01-01T00:00:00Z");
	}

	@SuppressWarnings("unchecked")
	private static Map<String, Object> decode(Resource resource) throws Exception {
		try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
			resource.write(out);
			return CODEC.dec()
				.from(out.toString("UTF-8"))
				.get(Map.class);
		}
	}

	// #62
	@Test
	public void cycloneDxLicenseUrl() throws Exception {
		assertThat(cdxLicenses(model(SbomLicense.spdx("BSD-3-Clause")
			.withUrl("https://www.antlr.org/license.html"))))
				.containsExactly(
					Map.of("license", Map.of("id", "BSD-3-Clause", "url", "https://www.antlr.org/license.html",
						"acknowledgement", "concluded")));
		assertThat(cdxLicenses(model(SbomLicense.named("https://example.org/l")
			.withUrl("https://example.org/l"))))
				.containsExactly(Map.of("license", Map.of("name", "https://example.org/l", "url", "https://example.org/l",
					"acknowledgement", "concluded")));
	}

	@Test
	@SuppressWarnings("unchecked")
	public void spdxLicenseRefSeeAlso() throws Exception {
		Map<String, Object> doc = decode(new SpdxSerializer().serialize(model(SbomLicense.named("Vendor License")
			.withUrl("https://example.org/l")), config(SbomFormat.SPDX)));
		assertThat((List<Map<String, Object>>) doc.get("hasExtractedLicensingInfos")).singleElement()
			.satisfies(info -> assertThat(info).containsEntry("seeAlsos", List.of("https://example.org/l")));
	}
}
