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

import java.util.List;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

import org.junit.jupiter.api.Test;

import org.gecko.bnd.sbom.LicenseResolver;
import org.gecko.bnd.sbom.model.SbomLicense;

/**
 * Unit tests for {@link LicenseResolver} seams using in-memory manifests / text (no workspace).
 */
public class LicenseResolverTest {

	private final LicenseResolver resolver = new LicenseResolver();

	@Test
	public void spdxIdFromBundleLicense() {
		List<SbomLicense> licenses = resolver.fromManifest(manifest("Apache-2.0"));
		assertThat(licenses).hasSize(1);
		assertThat(licenses.get(0)
			.spdxId()).isEqualTo("Apache-2.0");
	}

	@Test
	public void urlBundleLicenseIsMappedToSpdxId() {
		assertThat(resolver.fromManifest(manifest("https://opensource.org/licenses/MIT"))
			.get(0)
			.spdxId()).isEqualTo("MIT");
	}

	@Test
	public void multipleLicensesFromHeader() {
		List<SbomLicense> licenses = resolver.fromManifest(manifest("Apache-2.0, MIT"));
		assertThat(licenses).hasSize(2);
		assertThat(licenses.get(0)
			.spdxId()).isEqualTo("Apache-2.0");
		assertThat(licenses.get(1)
			.spdxId()).isEqualTo("MIT");
	}

	@Test
	public void unrecognizedLicenseKeptAsFreeText() {
		SbomLicense license = resolver.fromManifest(manifest("My Custom License"))
			.get(0);
		assertThat(license.spdxId()).isNull();
		assertThat(license.name()).isEqualTo("My Custom License");
	}

	@Test
	public void externalMarkerYieldsNoLicense() {
		assertThat(resolver.fromManifest(manifest("<<EXTERNAL>>"))).isEmpty();
	}

	@Test
	public void noHeaderYieldsNoLicense() {
		assertThat(resolver.fromManifest(manifest(null))).isEmpty();
		assertThat(resolver.fromManifest(null)).isEmpty();
	}

	@Test
	public void sniffsSpdxIdFromLicenseFileText() {
		assertThat(resolver.fromLicenseText("Apache License\nVersion 2.0, January 2004\n...")
			.get(0)
			.spdxId()).isEqualTo("Apache-2.0");
		assertThat(resolver
			.fromLicenseText("MIT License\n\nPermission is hereby granted, free of charge, to any person...")
			.get(0)
			.spdxId()).isEqualTo("MIT");
		assertThat(resolver.fromLicenseText("Eclipse Public License - v 2.0\n\nTHE ACCOMPANYING PROGRAM...")
			.get(0)
			.spdxId()).isEqualTo("EPL-2.0");
		assertThat(resolver.fromLicenseText(
			"Redistribution and use in source and binary forms, with or without modification...\nNeither the name of the copyright holder...")
			.get(0)
			.spdxId()).isEqualTo("BSD-3-Clause");
	}

	@Test
	public void unidentifiedLicenseFileKeepsFirstMeaningfulLineAsName() {
		SbomLicense license = resolver.fromLicenseText(
			"Copyright 2026 Example Corp\n\nAcme Proprietary License\n\nAll rights reserved.")
			.get(0);
		assertThat(license.spdxId()).isNull();
		assertThat(license.name()).isEqualTo("Acme Proprietary License");
	}

	@Test
	public void emptyLicenseTextYieldsNothing() {
		assertThat(resolver.fromLicenseText(null)).isEmpty();
		assertThat(resolver.fromLicenseText("\n\n")).isEmpty();
	}

	private static Manifest manifest(String bundleLicense) {
		Manifest manifest = new Manifest();
		Attributes main = manifest.getMainAttributes();
		main.putValue("Manifest-Version", "1.0");
		if (bundleLicense != null) {
			main.putValue("Bundle-License", bundleLicense);
		}
		return manifest;
	}
}
