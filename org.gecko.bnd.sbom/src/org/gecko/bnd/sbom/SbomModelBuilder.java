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
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.Manifest;

import aQute.bnd.build.Container;
import aQute.bnd.build.Project;
import aQute.bnd.header.OSGiHeader;
import aQute.bnd.osgi.Constants;
import aQute.bnd.osgi.Jar;
import org.gecko.bnd.sbom.model.MavenCoordinates;
import org.gecko.bnd.sbom.model.SbomComponent;
import org.gecko.bnd.sbom.model.SbomComponent.Category;
import org.gecko.bnd.sbom.model.SbomLayer;
import org.gecko.bnd.sbom.model.SbomLevel;
import org.gecko.bnd.sbom.model.SbomLicense;
import org.gecko.bnd.sbom.model.SbomModel;
import aQute.lib.hex.Hex;
import aQute.lib.io.IO;

/**
 * Builds the format-neutral {@link SbomModel} from the resolved run model. This is where the
 * OSGi build truth lives; format details are left to the serializer.
 */
public final class SbomModelBuilder {

	private final Project			project;
	private final SbomConfig		config;
	private final PurlResolver		purlResolver;
	private final LicenseResolver	licenseResolver	= new LicenseResolver();
	private final EmbeddedResolver	embeddedResolver;
	private final OriginResolver	originResolver;
	/** de-duplicates components that appear in more than one layer (bsn|version). */
	private final Set<String>		seen			= new LinkedHashSet<>();
	private Collection<Container>	runbundles		= Collections.emptyList();
	/** analysis steps that failed, declared in the BOM */
	private final List<String>					problems	= new ArrayList<>();
	/** manifests of the components, for the dependency graph */
	private final Map<SbomComponent, Manifest>	manifests	= new LinkedHashMap<>();

	public SbomModelBuilder(Project project, SbomConfig config) {
		this.project = project;
		this.config = config;
		this.purlResolver = new PurlResolver(project);
		this.originResolver = new OriginResolver(project.getRepositories());
		this.embeddedResolver = new EmbeddedResolver(purlResolver);
	}

	public SbomModelBuilder withRunbundles(Collection<Container> runbundles) {
		this.runbundles = runbundles;
		return this;
	}

	public SbomModel build() throws Exception {
		// #15: identity of the application — overridable through -sbom, otherwise what the
		// workspace declares for its artifacts (-groupid, Bundle-Version, Bundle-SCM, Bundle-DocURL)
		SbomModel model = new SbomModel()
			.setApplicationName(firstOf(config.applicationName(), project.getName()))
			.setApplicationGroup(firstOf(config.applicationGroup(), project.getProperty(Constants.GROUPID)))
			.setApplicationVersion(firstOf(config.applicationVersion(), project.getProperty(Constants.BUNDLE_VERSION)))
			.setApplicationPurl(config.applicationPurl())
			// CWE-200: URLs are published without credentials, query or fragment
			.setVcsUrl(Limits.publishableUrl(scmUrl(project.getProperty(Constants.BUNDLE_SCM))))
			.setWebsiteUrl(Limits.publishableUrl(firstOf(project.getProperty(Constants.BUNDLE_DOCURL))));
		Tools.current()
			.forEach(model::addTool);
		config.properties()
			.forEach(model::addProperty);

		// View 2, A2.1: the resolved application bundles.
		add(model, runbundles, null, SbomLayer.RUNBUNDLE);

		// View 2, A2.2: the framework infrastructure the bundles run on. -runfw and -runpath are
		// what ends up on the framework's class path; -runsystempackages/-runsystemcapabilities
		// only declare exports from there (or from the JDK) and bring no artifact of their own.
		// Both accessors return fully resolved Containers with maven-* attributes, so the same
		// PURL/license resolution applies.
		add(model, project.getRunFw(), Category.FRAMEWORK, SbomLayer.RUNFW);
		add(model, project.getRunpath(), Category.FRAMEWORK, SbomLayer.RUNPATH);

		// #13: who depends on whom, from the manifests of the resolved set
		DependencyGraph graph = new DependencyGraph(manifests);
		graph.edges()
			.forEach((from, to) -> to.forEach(target -> model.addDependency(from, target)));
		// #8: a bundle depends on the libraries it embeds
		for (SbomComponent component : model.getComponents()) {
			for (SbomComponent embedded : component.getEmbedded()) {
				model.addDependency(component, embedded);
			}
		}
		graph.roots(project.getProperty(Constants.RUNREQUIRES))
			.forEach(model::addApplicationDependency);
		for (SbomComponent component : model.getComponents()) {
			if (component.getCategory() == Category.FRAMEWORK) {
				model.addApplicationDependency(component);
			}
		}

		// A2.5/Q4: what this SBOM cannot see is declared, not silently omitted.
		model.setDependenciesComplete(false);
		model.addKnownUnknown("The Java runtime is not part of this SBOM; packages the bundles take from it "
			+ "(system packages, boot delegation) have no component and no dependency edge");
		model.addKnownUnknown("DynamicImport-Package is not resolved");
		graph.skipped()
			.forEach(bsn -> problems.add("No dependency edges for " + bsn + ": its manifest could not be read"));
		problems.forEach(model::addKnownUnknown);

		return model;
	}

	private void add(SbomModel model, Collection<Container> containers, Category category, SbomLayer layer)
		throws Exception {
		if (containers == null) {
			return;
		}
		for (Container container : containers) {
			String key = container.getBundleSymbolicName() + "|" + container.getVersion();
			if (seen.add(key)) {
				SbomComponent component = toComponent(container, category).setLayer(layer);
				model.addComponent(component);
				manifests.put(component, container.getManifest());
			}
		}
	}

	private SbomComponent toComponent(Container container, Category category) throws Exception {
		SbomComponent component = new SbomComponent().setBsn(container.getBundleSymbolicName())
			.setVersion(container.getVersion())
			.setCategory(category);

		// Q3: staged identity resolution → Maven coordinates + PURL; otherwise mark honestly as
		// unverified.
		MavenCoordinates maven = attempt(component, "identity", () -> purlResolver.resolve(container));
		if (maven == null) {
			// #9: coordinates configured for a bundle from p2/OBR that is also on Maven
			maven = config.mavenMapping(container.getBundleSymbolicName(), container.getVersion());
			if (maven != null) {
				component.setIdentitySource("configured");
			}
		}
		if (maven != null) {
			component.setMaven(maven)
				.setPurl(Purl.maven(maven));
		} else {
			component.setUnverifiedIdentity(true);
		}

		// #9: where it came from
		OriginResolver.Origin origin = attempt(component, "origin", () -> originResolver.resolve(container));
		if (origin != null) {
			component.setRepositoryName(origin.repositoryName())
				.setRepositoryKind(origin.kind())
				.setDistributionUrl(origin.distributionUrl());
		}

		// #8: libraries repackaged or embedded in the bundle
		File jarFile = container.getFile();
		if (jarFile != null && jarFile.isFile()) {
			MavenCoordinates own = maven;
			List<SbomComponent> embedded = attempt(component, "embedded libraries", () -> {
				try (Jar jar = new Jar(jarFile)) {
					// a bundle built in this workspace also shows what it inlined from its build path
					Project producer = container.getType() == Container.TYPE.PROJECT ? container.getProject() : null;
					return embeddedResolver.resolve(jar, own, config.level()
						.includes(SbomLevel.MEDIUM), producer);
				}
			});
			if (embedded != null) {
				embedded.forEach(component::addEmbedded);
			}
		}

		// medium+: hash + filename + license (BSI-driven, see §7).
		if (config.level()
			.includes(SbomLevel.MEDIUM)) {
			File file = container.getFile();
			if (file != null && file.isFile()) {
				component.setFilename(file.getName());
				component.setSha512(sha512(file));
			}
			List<SbomLicense> licenses = attempt(component, "license", () -> licenseResolver.resolve(container));
			if (licenses != null) {
				licenses.forEach(component::addLicense);
			}
		}

		return component;
	}

	/** The first value that is not blank, or {@code null}. */
	static String firstOf(String... values) {
		for (String value : values) {
			if (value != null && !value.isBlank()) {
				return value.trim();
			}
		}
		return null;
	}

	/** The {@code url} of a {@code Bundle-SCM} header ({@code url=..., connection=...}). */
	static String scmUrl(String bundleScm) {
		if (bundleScm == null || bundleScm.isBlank()) {
			return null;
		}
		try {
			return firstOf(OSGiHeader.parseProperties(bundleScm)
				.get("url"));
		} catch (IllegalArgumentException e) {
			return null;
		}
	}

	/** One step of analysing a component, which may fail on what the artifact contains. */
	@FunctionalInterface
	private interface Step<T> {
		T run() throws Exception;
	}

	/**
	 * CWE-754: a broken jar, manifest or POM must not abort the whole export, nor be silently
	 * skipped. The step's result is dropped, the component stays in the SBOM, and the failure is
	 * reported as a bnd warning and as a known unknown of the BOM.
	 */
	private <T> T attempt(SbomComponent component, String what, Step<T> step) {
		try {
			return step.run();
		} catch (Exception e) {
			String message = "Could not determine the " + what + " of " + component.getBsn() + " "
				+ component.getVersion() + ": " + e;
			project.warning("%s", message);
			problems.add(message);
			return null;
		}
	}

	/** Streamed, so a large bundle is never held in memory as a whole (CWE-400). */
	private static String sha512(File file) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-512");
		try (InputStream in = IO.stream(file)) {
			byte[] buffer = new byte[64 * 1024];
			int n;
			while ((n = in.read(buffer)) > 0) {
				md.update(buffer, 0, n);
			}
		}
		return Hex.toHexString(md.digest());
	}
}
