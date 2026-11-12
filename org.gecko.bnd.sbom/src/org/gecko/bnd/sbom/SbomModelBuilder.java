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
import java.security.MessageDigest;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.jar.Manifest;

import aQute.bnd.build.Container;
import aQute.bnd.build.Project;
import aQute.bnd.header.OSGiHeader;
import aQute.bnd.osgi.Constants;
import org.gecko.bnd.sbom.model.MavenCoordinates;
import org.gecko.bnd.sbom.model.SbomComponent;
import org.gecko.bnd.sbom.model.SbomComponent.Category;
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
	/** de-duplicates components that appear in more than one layer (bsn|version). */
	private final Set<String>		seen			= new LinkedHashSet<>();
	private Collection<Container>	runbundles		= Collections.emptyList();
	/** manifests of the components, for the dependency graph */
	private final Map<SbomComponent, Manifest>	manifests	= new LinkedHashMap<>();

	public SbomModelBuilder(Project project, SbomConfig config) {
		this.project = project;
		this.config = config;
		this.purlResolver = new PurlResolver(project);
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
			.setVcsUrl(scmUrl(project.getProperty(Constants.BUNDLE_SCM)))
			.setWebsiteUrl(firstOf(project.getProperty(Constants.BUNDLE_DOCURL)));
		Tools.current()
			.forEach(model::addTool);
		config.properties()
			.forEach(model::addProperty);

		// View 2, A2.1: the resolved application bundles.
		add(model, runbundles, null);

		// View 2, A2.2 (scope for now: -runfw + -runpath only): the framework infrastructure
		// the bundles run on. Both accessors return fully resolved Containers with maven-*
		// attributes, so the same PURL/license resolution applies.
		add(model, project.getRunFw(), Category.FRAMEWORK);
		add(model, project.getRunpath(), Category.FRAMEWORK);

		// #13: who depends on whom, from the manifests of the resolved set
		DependencyGraph graph = new DependencyGraph(manifests);
		graph.edges()
			.forEach((from, to) -> to.forEach(target -> model.addDependency(from, target)));
		graph.roots(project.getProperty(Constants.RUNREQUIRES))
			.forEach(model::addApplicationDependency);
		for (SbomComponent component : model.getComponents()) {
			if (component.getCategory() == Category.FRAMEWORK) {
				model.addApplicationDependency(component);
			}
		}

		// A2.5/Q4: system packages, boot delegation and DynamicImport-Package are out of the
		// current scope and are declared as gaps rather than silently omitted.
		model.setDependenciesComplete(false);
		model.addKnownUnknown(
			"Framework scope limited to -runfw/-runpath; system packages, boot delegation and DynamicImport-Package not resolved");

		return model;
	}

	private void add(SbomModel model, Collection<Container> containers, Category category) throws Exception {
		if (containers == null) {
			return;
		}
		for (Container container : containers) {
			String key = container.getBundleSymbolicName() + "|" + container.getVersion();
			if (seen.add(key)) {
				SbomComponent component = toComponent(container, category);
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
		MavenCoordinates maven = purlResolver.resolve(container);
		if (maven != null) {
			component.setMaven(maven)
				.setPurl(Purl.maven(maven));
		} else {
			component.setUnverifiedIdentity(true);
		}

		// medium+: hash + filename + license (BSI-driven, see §7).
		if (config.level()
			.includes(SbomLevel.MEDIUM)) {
			File file = container.getFile();
			if (file != null && file.isFile()) {
				component.setFilename(file.getName());
				component.setSha512(sha512(file));
			}
			for (SbomLicense license : licenseResolver.resolve(container)) {
				component.addLicense(license);
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

	private static String sha512(File file) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-512");
		return Hex.toHexString(md.digest(IO.read(file)));
	}
}
