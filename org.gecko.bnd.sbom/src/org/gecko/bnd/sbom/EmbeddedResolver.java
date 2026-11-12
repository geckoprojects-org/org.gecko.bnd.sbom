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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.jar.Manifest;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.gecko.bnd.sbom.model.MavenCoordinates;
import org.gecko.bnd.sbom.model.SbomComponent;
import org.gecko.bnd.sbom.model.SbomLicense;

import aQute.bnd.build.Container;
import aQute.bnd.build.Project;
import aQute.bnd.header.Attrs;
import aQute.bnd.header.Parameters;
import aQute.bnd.osgi.Constants;
import aQute.bnd.osgi.Domain;
import aQute.bnd.osgi.Jar;
import aQute.bnd.osgi.Resource;
import aQute.lib.hex.Hex;
import aQute.lib.io.IO;

/**
 * Libraries repackaged or embedded in a bundle (#8). A CVE is published against the
 * coordinates of the original library, so the bundle's own coordinates are not enough.
 * <p>
 * Found are
 * <ul>
 * <li>every {@code pom.properties} under {@code META-INF/maven/} or
 * {@code OSGI-OPT/src/META-INF/maven/} whose group and artifact differ from the bundle's own —
 * a library whose classes were repackaged into the bundle</li>
 * <li>every jar on the {@code Bundle-ClassPath}, identified by its own {@code pom.properties},
 * otherwise kept by its path with an unverified identity</li>
 * <li>for a bundle built in this workspace: every {@code -buildpath} entry whose classes the
 * bundle contains — what {@code -conditionalpackage}, {@code Private-Package} or
 * {@code -includeresource: @x.jar!/...} pulled in, which leaves no {@code pom.properties}
 * behind. The original is the build path entry, with the coordinates its repository knows.
 * Packages the project compiles itself are not counted. Bundles built elsewhere do not carry
 * their build path, so for them this part finds nothing.</li>
 * </ul>
 * With {@code withDetails} (level medium) an embedded library also gets its licenses from the
 * {@code pom.xml} next to its {@code pom.properties}, and an embedded jar its SHA-512.
 */
public final class EmbeddedResolver {

	private static final Pattern	POM_PROPERTIES	= Pattern
		.compile("(?:OSGI-OPT/src/)?META-INF/maven/[^/]+/[^/]+/pom\\.properties");

	private final LicenseResolver	licenseResolver	= new LicenseResolver();
	private final PurlResolver		purlResolver;

	/** @param purlResolver identifies build path entries (#8, inlined packages) */
	public EmbeddedResolver(PurlResolver purlResolver) {
		this.purlResolver = purlResolver;
	}

	/**
	 * @param jar the bundle
	 * @param own the bundle's own Maven coordinates, may be {@code null}
	 * @param withDetails add licenses and hashes (level medium)
	 */
	public List<SbomComponent> resolve(Jar jar, MavenCoordinates own, boolean withDetails) throws Exception {
		return resolve(jar, own, withDetails, null);
	}

	/**
	 * @param producer the workspace project that built the bundle, or {@code null} for a bundle
	 *            from a repository
	 */
	public List<SbomComponent> resolve(Jar jar, MavenCoordinates own, boolean withDetails, Project producer)
		throws Exception {
		List<SbomComponent> result = new ArrayList<>();
		Set<String> seen = new LinkedHashSet<>();
		if (own != null) {
			seen.add(ga(own));
		}

		// repackaged: pom.properties of other libraries
		for (Map.Entry<String, Resource> entry : jar.getResources()
			.entrySet()) {
			String path = entry.getKey();
			if (!POM_PROPERTIES.matcher(path)
				.matches()) {
				continue;
			}
			MavenCoordinates coordinates = coordinates(entry.getValue());
			if (coordinates == null || !seen.add(ga(coordinates))) {
				continue;
			}
			SbomComponent component = library(coordinates, path);
			if (withDetails) {
				// the pom.xml may sit beside either copy: META-INF/maven or the sources in OSGI-OPT
				String dir = "META-INF/maven/" + coordinates.groupId() + "/" + coordinates.artifactId() + "/pom.xml";
				for (String candidate : List.of(dir, "OSGI-OPT/src/" + dir)) {
					Resource pom = jar.getResource(candidate);
					if (pom == null) {
						continue;
					}
					try (InputStream in = pom.openInputStream()) {
						licenseResolver.fromPom(in)
							.forEach(component::addLicense);
					}
					if (!component.getLicenses()
						.isEmpty()) {
						break;
					}
				}
			}
			result.add(component);
		}

		// embedded: jars on the Bundle-ClassPath
		Manifest manifest = jar.getManifest();
		if (manifest != null) {
			Parameters classpath = Domain.domain(manifest)
				.getParameters(Constants.BUNDLE_CLASSPATH);
			for (Map.Entry<String, Attrs> entry : classpath.entrySet()) {
				String path = entry.getKey()
					.trim();
				if (path.equals(".") || path.isEmpty()) {
					continue;
				}
				Resource nested = jar.getResource(path.startsWith("/") ? path.substring(1) : path);
				if (nested == null || !path.endsWith(".jar")) {
					continue; // a directory on the class path is part of the bundle itself
				}
				SbomComponent component = nestedJar(path, nested, seen, withDetails);
				if (component != null) {
					result.add(component);
				}
			}
		}

		// inlined: classes from the build path of the project that built the bundle
		if (producer != null) {
			result.addAll(inlined(jar, producer, seen, withDetails));
		}
		return result;
	}

	private List<SbomComponent> inlined(Jar bundle, Project producer, Set<String> seen, boolean withDetails)
		throws Exception {
		Set<String> packages = classPackages(bundle);
		packages.removeAll(ownPackages(producer.getOutput()));
		List<SbomComponent> result = new ArrayList<>();
		if (packages.isEmpty()) {
			return result;
		}
		for (Container entry : producer.getBuildpath()) {
			File file = entry.getFile();
			if (file == null || !file.isFile()) {
				continue;
			}
			Set<String> shared;
			try (Jar original = new Jar(file)) {
				shared = classPackages(original);
			}
			shared.retainAll(packages);
			if (shared.isEmpty()) {
				continue;
			}
			MavenCoordinates coordinates = purlResolver.resolve(entry);
			if (coordinates != null && !seen.add(ga(coordinates))) {
				continue;
			}
			String where = "packages " + summary(shared) + " from -buildpath";
			SbomComponent component;
			if (coordinates != null) {
				component = library(coordinates, where);
			} else {
				component = new SbomComponent().setBsn(entry.getBundleSymbolicName())
					.setVersion(entry.getVersion())
					.setEmbeddedPath(where)
					.setUnverifiedIdentity(true);
			}
			if (withDetails) {
				licenseResolver.resolve(entry)
					.forEach(component::addLicense);
			}
			result.add(component);
		}
		return result;
	}

	/** Packages (as dotted names) that hold at least one class, outside META-INF and OSGI-OPT. */
	static Set<String> classPackages(Jar jar) {
		Set<String> packages = new TreeSet<>();
		for (String path : jar.getResources()
			.keySet()) {
			if (!path.endsWith(".class") || path.startsWith("META-INF/") || path.startsWith("OSGI-OPT/")) {
				continue;
			}
			int slash = path.lastIndexOf('/');
			if (slash > 0 && !path.endsWith("module-info.class")) {
				packages.add(path.substring(0, slash)
					.replace('/', '.'));
			}
		}
		return packages;
	}

	/** Packages the project compiles itself: the class directories of its output folder. */
	private static Set<String> ownPackages(File output) throws Exception {
		Set<String> packages = new TreeSet<>();
		if (output == null || !output.isDirectory()) {
			return packages;
		}
		Path root = output.toPath();
		try (Stream<Path> files = Files.walk(root)) {
			files.filter(p -> p.toString()
				.endsWith(".class"))
				.map(p -> root.relativize(p.getParent() == null ? root : p.getParent())
					.toString()
					.replace(File.separatorChar, '.'))
				.filter(name -> !name.isEmpty())
				.forEach(packages::add);
		}
		return packages;
	}

	private static String summary(Set<String> packages) {
		List<String> list = new ArrayList<>(packages);
		if (list.size() <= 3) {
			return String.join(", ", list);
		}
		return String.join(", ", list.subList(0, 3)) + " and " + (list.size() - 3) + " more";
	}

	private SbomComponent nestedJar(String path, Resource resource, Set<String> seen, boolean withDetails)
		throws Exception {
		byte[] bytes;
		try (InputStream in = resource.openInputStream()) {
			bytes = IO.read(in);
		}
		MavenCoordinates coordinates = null;
		List<SbomLicense> licenses = List.of();
		try (Jar nested = new Jar(path, new ByteArrayInputStream(bytes))) {
			for (Map.Entry<String, Resource> entry : nested.getResources()
				.entrySet()) {
				if (POM_PROPERTIES.matcher(entry.getKey())
					.matches()) {
					coordinates = coordinates(entry.getValue());
					if (coordinates != null) {
						break;
					}
				}
			}
			if (withDetails) {
				licenses = licenseResolver.resolve(nested);
			}
		}
		if (coordinates != null && !seen.add(ga(coordinates))) {
			return null; // the same library was already found through its pom.properties
		}
		SbomComponent component;
		if (coordinates != null) {
			component = library(coordinates, path);
		} else {
			int slash = path.lastIndexOf('/');
			component = new SbomComponent().setBsn(path.substring(slash + 1))
				.setEmbeddedPath(path)
				.setUnverifiedIdentity(true);
		}
		if (withDetails) {
			component.setFilename(path.substring(path.lastIndexOf('/') + 1));
			component.setSha512(Hex.toHexString(MessageDigest.getInstance("SHA-512")
				.digest(bytes)));
			licenses.forEach(component::addLicense);
		}
		return component;
	}

	private static SbomComponent library(MavenCoordinates coordinates, String path) {
		return new SbomComponent().setMaven(coordinates)
			.setPurl(Purl.maven(coordinates))
			.setEmbeddedPath(path);
	}

	private static MavenCoordinates coordinates(Resource resource) throws Exception {
		Properties properties = new Properties();
		try (InputStream in = resource.openInputStream()) {
			properties.load(in);
		}
		String version = properties.getProperty("version");
		if (version != null && version.contains("${")) {
			return null; // an unfiltered template, not a real coordinate
		}
		return MavenCoordinates.of(properties.getProperty("groupId"), properties.getProperty("artifactId"), version,
			null, null);
	}

	private static String ga(MavenCoordinates coordinates) {
		return coordinates.groupId() + ":" + coordinates.artifactId();
	}
}
