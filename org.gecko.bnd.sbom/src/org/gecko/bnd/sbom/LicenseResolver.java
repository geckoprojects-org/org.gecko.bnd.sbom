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

import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.jar.Manifest;

import javax.xml.parsers.DocumentBuilderFactory;

import org.gecko.bnd.sbom.model.SbomLicense;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import aQute.bnd.build.Container;
import aQute.bnd.header.Attrs;
import aQute.bnd.header.Parameters;
import aQute.bnd.osgi.Constants;
import aQute.bnd.osgi.Domain;
import aQute.bnd.osgi.Jar;
import aQute.bnd.osgi.Processor;
import aQute.bnd.osgi.Resource;
import aQute.lib.io.IO;
import aQute.libg.glob.PathSet;

/**
 * Detects a component's license(s) (medium+) from, in order:
 * <ol>
 * <li>the OSGi-native {@code Bundle-License} manifest header — which may list several licenses;
 * each is an SPDX id, an SPDX expression, a known name or a known URL</li>
 * <li>the {@code <licenses>} of the artifact's POM next to the JAR in the Maven repository
 * (Eclipse bundles such as EMF declare their license only there)</li>
 * <li>the {@code <licenses>} of a {@code META-INF/maven/**}{@code /pom.xml} inside the JAR</li>
 * <li>a license file embedded in the JAR ({@code LICENSE*}, {@code COPYING*}): a conservative,
 * high-precision text sniff yields an SPDX id, otherwise the file's first meaningful line is
 * kept as free-text {@code license.name}</li>
 * <li>an Eclipse {@code about.html}, by text sniff only (its first line is markup, not a
 * license name)</li>
 * </ol>
 * The guiding rule stays: resolve to a validated SPDX id when confident, otherwise keep raw
 * text — never assert a wrong SPDX id. Returns an empty list when nothing is found.
 */
public final class LicenseResolver {

	private static final String		EXTERNAL		= "<<EXTERNAL>>";
	private static final String		LINK			= "link";
	private static final PathSet	EMBEDDED_POM	= new PathSet("META-INF/maven/*/*/pom.xml");
	private static final String		ABOUT			= "about.html";

	public List<SbomLicense> resolve(Container container) throws Exception {
		List<SbomLicense> fromManifest = fromManifest(container.getManifest());
		if (!fromManifest.isEmpty()) {
			return fromManifest;
		}
		File file = container.getFile();
		if (file == null || !file.isFile()) {
			return Collections.emptyList();
		}
		List<SbomLicense> fromRepositoryPom = fromRepositoryPom(file);
		if (!fromRepositoryPom.isEmpty()) {
			return fromRepositoryPom;
		}
		try (Jar jar = new Jar(file)) {
			List<SbomLicense> fromEmbeddedPom = fromEmbeddedPom(jar);
			if (!fromEmbeddedPom.isEmpty()) {
				return fromEmbeddedPom;
			}
			List<SbomLicense> fromLicenseFile = fromLicenseFile(jar);
			if (!fromLicenseFile.isEmpty()) {
				return fromLicenseFile;
			}
			return fromAbout(jar);
		}
	}

	/**
	 * One license value as an SPDX id, an SPDX expression or — when neither the value nor its
	 * link is recognized — as free text.
	 */
	static SbomLicense recognize(String value, String link) {
		String recognized = SpdxLicenses.toExpression(value);
		if (recognized == null) {
			recognized = SpdxLicenses.toExpression(link);
		}
		if (recognized == null) {
			return SbomLicense.named(value);
		}
		return SpdxLicenses.toId(recognized) != null ? SbomLicense.spdx(recognized) : SbomLicense.expression(recognized);
	}

	/** {@code <artifactId>-<version>.pom} next to the JAR, as Maven repositories store it. */
	private List<SbomLicense> fromRepositoryPom(File jar) throws Exception {
		String name = jar.getName();
		if (!name.endsWith(".jar")) {
			return Collections.emptyList();
		}
		File pom = new File(jar.getParentFile(), name.substring(0, name.length() - 4) + ".pom");
		if (!pom.isFile()) {
			return Collections.emptyList();
		}
		try (InputStream in = IO.stream(pom)) {
			return fromPom(in);
		}
	}

	private List<SbomLicense> fromEmbeddedPom(Jar jar) throws Exception {
		Optional<Resource> pom = jar.getResources(EMBEDDED_POM.matches())
			.findFirst();
		if (pom.isEmpty()) {
			return Collections.emptyList();
		}
		try (InputStream in = pom.get()
			.openInputStream()) {
			return fromPom(in);
		}
	}

	/** Testable seam: the {@code <licenses>} of a POM. Only the POM itself, no parent. */
	public List<SbomLicense> fromPom(InputStream pom) {
		Document document;
		try {
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setNamespaceAware(true);
			// a POM from a repository is untrusted input: no DTDs, no external entities
			factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
			factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
			factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
			factory.setXIncludeAware(false);
			factory.setExpandEntityReferences(false);
			document = factory.newDocumentBuilder()
				.parse(pom);
		} catch (Exception e) {
			return Collections.emptyList();
		}
		List<SbomLicense> result = new ArrayList<>();
		NodeList licenses = document.getElementsByTagNameNS("*", "license");
		for (int i = 0; i < licenses.getLength(); i++) {
			Element license = (Element) licenses.item(i);
			// only project/licenses/license, not a <license> in some plugin configuration
			if (!(license.getParentNode() instanceof Element parent) || !"licenses".equals(parent.getLocalName())
				|| !(parent.getParentNode() instanceof Element project) || !"project".equals(project.getLocalName())) {
				continue;
			}
			String name = childText(license, "name");
			String url = childText(license, "url");
			if (name != null) {
				result.add(recognize(name, url));
			} else if (url != null) {
				result.add(recognize(url, null));
			}
		}
		return result;
	}

	private static String childText(Element element, String localName) {
		for (Node child = element.getFirstChild(); child != null; child = child.getNextSibling()) {
			if (child instanceof Element e && localName.equals(e.getLocalName())) {
				String text = e.getTextContent()
					.trim();
				return text.isEmpty() ? null : text;
			}
		}
		return null;
	}

	/** Last resort for Eclipse bundles: {@code about.html}, recognized by its text only. */
	private List<SbomLicense> fromAbout(Jar jar) throws Exception {
		Resource about = jar.getResource(ABOUT);
		if (about == null) {
			return Collections.emptyList();
		}
		try (InputStream in = about.openInputStream()) {
			String text = IO.collect(in)
				.replaceAll("<[^>]*>", " ");
			String spdx = sniff(text);
			return spdx != null ? Collections.singletonList(SbomLicense.spdx(spdx)) : Collections.emptyList();
		}
	}

	/** Testable seam: all licenses declared in a manifest's {@code Bundle-License} header. */
	public List<SbomLicense> fromManifest(Manifest manifest) {
		if (manifest == null) {
			return Collections.emptyList();
		}

		Parameters licenses = Domain.domain(manifest)
			.getParameters(Constants.BUNDLE_LICENSE);

		List<SbomLicense> result = new ArrayList<>();
		for (Map.Entry<String, Attrs> entry : licenses.entrySet()) {
			String name = Processor.removeDuplicateMarker(entry.getKey())
				.trim();
			if (name.isEmpty() || EXTERNAL.equalsIgnoreCase(name)) {
				continue;
			}

			Attrs attrs = entry.getValue();
			result.add(recognize(name, attrs != null ? attrs.get(LINK) : null));
		}
		return result;
	}

	/** Fallback: the first {@code LICENSE}/{@code COPYING} file embedded in the JAR. */
	private List<SbomLicense> fromLicenseFile(Jar jar) throws Exception {
		String path = jar.getResources()
			.keySet()
			.stream()
			.filter(LicenseResolver::isLicenseFile)
			// prefer the shallowest, shortest path (e.g. root LICENSE over a nested copy)
			.min(Comparator.comparingInt((String p) -> p.split("/").length)
				.thenComparingInt(String::length))
			.orElse(null);
		if (path == null) {
			return Collections.emptyList();
		}
		Resource resource = jar.getResource(path);
		if (resource == null) {
			return Collections.emptyList();
		}
		try (InputStream in = resource.openInputStream()) {
			return fromLicenseText(IO.collect(in));
		}
	}

	/** Testable seam: identify a license from its full text (yields 0 or 1 license). */
	public List<SbomLicense> fromLicenseText(String text) {
		if (text == null) {
			return Collections.emptyList();
		}
		String spdx = sniff(text);
		if (spdx != null) {
			return Collections.singletonList(SbomLicense.spdx(spdx));
		}
		String firstLine = firstMeaningfulLine(text);
		return firstLine != null ? Collections.singletonList(SbomLicense.named(firstLine)) : Collections.emptyList();
	}

	/**
	 * Conservative, high-precision text match for the most common licenses. Order matters
	 * (LGPL before GPL, EPL-2.0 before 1.0). Anything unrecognized returns {@code null}.
	 */
	private static String sniff(String text) {
		String t = text.toLowerCase(Locale.ROOT);
		if (t.contains("apache license") && t.contains("version 2.0")) {
			return "Apache-2.0";
		}
		if (t.contains("permission is hereby granted, free of charge")) {
			return "MIT";
		}
		if (t.contains("eclipse public license")) {
			if (t.contains("2.0")) {
				return "EPL-2.0";
			}
			if (t.contains("1.0")) {
				return "EPL-1.0";
			}
		}
		if (t.contains("mozilla public license") && t.contains("2.0")) {
			return "MPL-2.0";
		}
		if (t.contains("gnu lesser general public license")) {
			if (t.contains("version 3")) {
				return "LGPL-3.0";
			}
			if (t.contains("version 2.1")) {
				return "LGPL-2.1";
			}
		}
		if (t.contains("gnu general public license")) {
			if (t.contains("version 3")) {
				return "GPL-3.0";
			}
			if (t.contains("version 2")) {
				return "GPL-2.0";
			}
		}
		if (t.contains("redistribution and use in source and binary forms")) {
			return t.contains("neither the name") ? "BSD-3-Clause" : "BSD-2-Clause";
		}
		return null;
	}

	private static String firstMeaningfulLine(String text) {
		for (String raw : text.split("\\R", 200)) {
			String line = raw.trim();
			if (line.isEmpty()) {
				continue;
			}
			String lower = line.toLowerCase(Locale.ROOT);
			if (lower.startsWith("copyright") || lower.startsWith("(c)") || lower.startsWith("©")) {
				continue;
			}
			if (!line.matches(".*\\p{L}.*")) {
				continue;
			}
			return line.length() > 120 ? line.substring(0, 120) : line;
		}
		return null;
	}

	private static boolean isLicenseFile(String path) {
		int slash = path.lastIndexOf('/');
		String base = (slash >= 0 ? path.substring(slash + 1) : path).toLowerCase(Locale.ROOT);
		return base.equals("license") || base.startsWith("license.") || base.startsWith("license-")
			|| base.equals("copying") || base.startsWith("copying.");
	}
}
