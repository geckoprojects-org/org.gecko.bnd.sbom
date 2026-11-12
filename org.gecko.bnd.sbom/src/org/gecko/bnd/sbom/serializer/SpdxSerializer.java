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
package org.gecko.bnd.sbom.serializer;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.gecko.bnd.sbom.SbomConfig;
import org.gecko.bnd.sbom.model.MavenCoordinates;
import org.gecko.bnd.sbom.model.SbomComponent;
import org.gecko.bnd.sbom.model.SbomLicense;
import org.gecko.bnd.sbom.model.SbomModel;
import org.gecko.bnd.sbom.model.SbomRefs;
import aQute.bnd.osgi.EmbeddedResource;
import aQute.bnd.osgi.Resource;
import aQute.lib.json.JSONCodec;

/**
 * Serializes the {@link SbomModel} as SPDX 2.3 JSON (second serializer, see Q1). Same
 * format-neutral model as {@link CycloneDxSerializer}; only the mapping differs. Built as
 * {@code Map}/{@code List} and encoded with bnd's {@link JSONCodec}, no external SPDX library.
 * <p>
 * SPDX is document/relationship-centric: each component becomes a {@code package}, linked from
 * the document via a {@code DESCRIBES} relationship. A PURL travels in {@code externalRefs}.
 * Licenses become a license expression ({@code A AND B}); a free-text license that has no SPDX
 * id is emitted as a {@code LicenseRef} declared in {@code hasExtractedLicensingInfos} (rather
 * than lost to {@code NOASSERTION}).
 */
public final class SpdxSerializer implements SbomSerializer {

	private static final String		SPDX_VERSION	= "SPDX-2.3";
	private static final String		NOASSERTION		= "NOASSERTION";
	private static final String		DOCUMENT_ID		= "SPDXRef-DOCUMENT";
	private static final String		NAMESPACE_BASE	= "https://spdx.org/spdxdocs/";
	private static final JSONCodec	CODEC			= new JSONCodec();

	@Override
	public String fileExtension() {
		return ".spdx.json";
	}

	@Override
	public Resource serialize(SbomModel model, SbomConfig config) throws Exception {
		String created = config.created()
			.toString();
		String appName = model.getApplicationName() != null ? model.getApplicationName() : "application";

		ExtractedLicenses extracted = new ExtractedLicenses();
		List<Object> packages = new ArrayList<>();
		List<Object> relationships = new ArrayList<>();
		SbomRefs refs = SbomRefs.of(model);
		for (SbomComponent component : model.getComponents()) {
			String spdxId = refs.spdxOf(component);
			packages.add(pkg(spdxId, component, extracted));
			relationships.add(relationship(DOCUMENT_ID, "DESCRIBES", spdxId));
		}

		Map<String, Object> doc = new LinkedHashMap<>();
		doc.put("spdxVersion", SPDX_VERSION);
		doc.put("dataLicense", "CC0-1.0");
		doc.put("SPDXID", DOCUMENT_ID);
		doc.put("name", appName);
		// #12: the same rule as CycloneDX's serialNumber — derived from the content, not the time
		doc.put("documentNamespace",
			NAMESPACE_BASE + sanitize(appName) + "-" + SerialNumbers.of(model, refs, config));
		doc.put("creationInfo", creationInfo(created, model));
		if (!extracted.infos.isEmpty()) {
			doc.put("hasExtractedLicensingInfos", extracted.infos);
		}
		doc.put("packages", packages);
		doc.put("relationships", relationships);

		String json = CODEC.enc()
			.indent("  ")
			.put(doc)
			.toString();
		return new EmbeddedResource(json, config.created()
			.toEpochMilli());
	}

	private Map<String, Object> creationInfo(String created, SbomModel model) {
		Map<String, Object> info = new LinkedHashMap<>();
		info.put("created", created);
		info.put("creators", listOf("Tool: bnd-SBOM-Exporter"));
		// A2.5/Q4: SPDX has no "aggregate" field; declare completeness + gaps in the comment.
		StringBuilder comment = new StringBuilder(
			model.isDependenciesComplete() ? "Dependencies complete." : "Dependencies incomplete.");
		for (String unknown : model.getKnownUnknowns()) {
			comment.append(" Known unknown: ")
				.append(unknown)
				.append('.');
		}
		info.put("comment", comment.toString());
		return info;
	}

	private Map<String, Object> pkg(String spdxId, SbomComponent component, ExtractedLicenses extracted) {
		Map<String, Object> pkg = new LinkedHashMap<>();
		pkg.put("SPDXID", spdxId);
		// Name and version agree with the PURL: Maven coordinates when verified, otherwise the
		// OSGi identity (#14).
		MavenCoordinates maven = component.getMaven();
		if (maven != null) {
			pkg.put("name", maven.artifactId());
			pkg.put("versionInfo", maven.version());
		} else {
			pkg.put("name", component.getBsn());
			if (component.getVersion() != null) {
				pkg.put("versionInfo", component.getVersion());
			}
		}
		pkg.put("downloadLocation", NOASSERTION);
		pkg.put("filesAnalyzed", false);

		String license = licenseExpression(component, extracted);
		pkg.put("licenseConcluded", license);
		pkg.put("licenseDeclared", license);

		if (component.getSha512() != null) {
			Map<String, Object> checksum = new LinkedHashMap<>();
			checksum.put("algorithm", "SHA512");
			checksum.put("checksumValue", component.getSha512());
			pkg.put("checksums", listOf(checksum));
		}
		if (component.getPurl() != null) {
			Map<String, Object> ref = new LinkedHashMap<>();
			ref.put("referenceCategory", "PACKAGE-MANAGER");
			ref.put("referenceType", "purl");
			ref.put("referenceLocator", component.getPurl());
			pkg.put("externalRefs", listOf(ref));
		}
		// SPDX 2.3 has no free properties: the OSGi identity, which the framework sees, goes into
		// the comment. Q3.b: an unresolvable identity is flagged, not given a fake purl.
		List<String> comment = new ArrayList<>();
		if (component.getBsn() != null) {
			comment.add("OSGi bundle: " + component.getBsn()
				+ (component.getVersion() != null ? " " + component.getVersion() : "") + ".");
		}
		if (component.isUnverifiedIdentity()) {
			comment.add("Identity unverified (reduced matchability): no reliable PURL.");
		}
		if (!comment.isEmpty()) {
			pkg.put("comment", String.join(" ", comment));
		}
		return pkg;
	}

	/**
	 * Builds an SPDX license expression from a component's licenses. SPDX ids go in verbatim;
	 * free-text licenses become {@code LicenseRef} entries. Multiple licenses are joined with
	 * {@code AND} — the OSGi {@code Bundle-License} header does not encode AND/OR, so the
	 * conservative conjunction is assumed. {@code NOASSERTION} when there is no license.
	 */
	private String licenseExpression(SbomComponent component, ExtractedLicenses extracted) {
		if (component.getLicenses()
			.isEmpty()) {
			return NOASSERTION;
		}
		List<String> parts = new ArrayList<>();
		for (SbomLicense license : component.getLicenses()) {
			parts.add(license.isSpdx() || license.isExpression() ? license.asOperand() : extracted.refFor(license.name()));
		}
		if (parts.size() == 1 && component.getLicenses()
			.get(0)
			.isExpression()) {
			return component.getLicenses()
				.get(0)
				.expression();
		}
		return String.join(" AND ", parts);
	}

	private static Map<String, Object> relationship(String from, String type, String to) {
		Map<String, Object> relationship = new LinkedHashMap<>();
		relationship.put("spdxElementId", from);
		relationship.put("relationshipType", type);
		relationship.put("relatedSpdxElement", to);
		return relationship;
	}

	/** SPDX ids and namespaces allow only letters, digits, '.' and '-'. */
	private static String sanitize(String value) {
		return value.trim()
			.toLowerCase(Locale.ROOT)
			.replaceAll("[^a-z0-9.-]", "-");
	}

	private static List<Object> listOf(Object element) {
		List<Object> list = new ArrayList<>();
		list.add(element);
		return list;
	}

	/**
	 * Per-document registry of free-text licenses → {@code LicenseRef-N}, accumulating the
	 * matching {@code hasExtractedLicensingInfos} entries. Identical names share one ref.
	 */
	private static final class ExtractedLicenses {

		private final Map<String, String>	refByName	= new LinkedHashMap<>();
		private final List<Object>			infos		= new ArrayList<>();

		String refFor(String name) {
			String existing = refByName.get(name);
			if (existing != null) {
				return existing;
			}
			String ref = "LicenseRef-" + refByName.size();
			refByName.put(name, ref);
			Map<String, Object> info = new LinkedHashMap<>();
			info.put("licenseId", ref);
			info.put("name", name);
			// extractedText is required; we only have the declared name, so use it as the text.
			info.put("extractedText", name);
			infos.add(info);
			return ref;
		}
	}
}
