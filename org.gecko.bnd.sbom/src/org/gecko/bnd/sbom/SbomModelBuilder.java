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
import java.util.Locale;
import java.util.Set;
import java.util.jar.Manifest;

import aQute.bnd.build.Container;
import aQute.bnd.build.Project;
import aQute.bnd.build.Workspace;
import aQute.bnd.build.model.EE;
import aQute.bnd.header.Attrs;
import aQute.bnd.header.OSGiHeader;
import aQute.bnd.header.Parameters;
import aQute.bnd.osgi.Constants;
import aQute.bnd.osgi.Jar;
import aQute.bnd.osgi.Processor;
import aQute.bnd.version.Version;
import org.gecko.bnd.sbom.model.MavenCoordinates;
import org.gecko.bnd.sbom.model.SbomComponent;
import org.gecko.bnd.sbom.model.SbomComponent.Category;
import org.gecko.bnd.sbom.model.SbomCreator;
import org.gecko.bnd.sbom.model.SbomLayer;
import org.gecko.bnd.sbom.model.SbomLevel;
import org.gecko.bnd.sbom.model.SbomLicense;
import org.gecko.bnd.sbom.model.SbomModel;
import aQute.lib.filter.Filter;
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
		String applicationGroup = firstOf(config.applicationGroup(), project.getProperty(Constants.GROUPID));
		SbomModel model = new SbomModel()
			.setApplicationName(firstOf(config.applicationName(), project.getName()))
			.setApplicationGroup(applicationGroup)
			.setApplicationVersion(firstOf(config.applicationVersion(),
				applicationVersion(applicationGroup, project.getProperty(Constants.BUNDLE_VERSION))))
			.setApplicationPurl(config.applicationPurl())
			// CWE-200: URLs are published without credentials, query or fragment
			.setVcsUrl(Limits.publishableUrl(scmUrl(project.getProperty(Constants.BUNDLE_SCM))))
			.setWebsiteUrl(Limits.publishableUrl(firstOf(project.getProperty(Constants.BUNDLE_DOCURL))));
		model.setCreator(creator());
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

		// medium+, BSI TR-03183-2 §3.2.1/§3.2.2/§5.1: the Java runtime is the first component
		// outside the scope of delivery. It is identified as a logical component with the
		// minimum version the application needs, and the bundles that require it depend on it.
		SbomComponent javaRuntime = config.level()
			.includes(SbomLevel.MEDIUM) ? javaRuntime() : null;
		if (javaRuntime != null) {
			model.addComponent(javaRuntime);
			for (Map.Entry<SbomComponent, Manifest> entry : manifests.entrySet()) {
				if (minimumEE(entry.getValue()) != null) {
					model.addDependency(entry.getKey(), javaRuntime);
				}
			}
			model.addApplicationDependency(javaRuntime);
		}
		for (SbomComponent component : model.getComponents()) {
			if (component.getCategory() == Category.FRAMEWORK) {
				model.addApplicationDependency(component);
			}
		}

		// A2.5/Q4: what this SBOM cannot see is declared, not silently omitted.
		model.setDependenciesComplete(false);
		model.addKnownUnknown(javaRuntime != null
			? "The Java runtime is not delivered; it is listed as the Java SE API with the minimum version the "
				+ "application requires, not as the runtime it is deployed on. Packages the bundles take from it "
				+ "(system packages, boot delegation) have no dependency edge of their own"
			: "The Java runtime is not part of this SBOM; packages the bundles take from it "
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

		// medium+: hash + filename + license + creator + file properties (BSI-driven, see §7).
		if (config.level()
			.includes(SbomLevel.MEDIUM)) {
			File file = container.getFile();
			if (file != null && file.isFile()) {
				component.setFilename(file.getName());
				component.setSha512(sha512(file));
				if (isJar(file.getName())) {
					setJarProperties(component);
				}
			}
			for (SbomComponent embedded : component.getEmbedded()) {
				setEmbeddedJarProperties(embedded);
			}
			Manifest manifest = attempt(component, "creator", container::getManifest);
			component.setCreator(Creators.fromManifest(manifest));
			List<SbomLicense> licenses = attempt(component, "license", () -> licenseResolver.resolve(container));
			if (licenses != null) {
				licenses.forEach(component::addLicense);
			}
		}

		return component;
	}

	/**
	 * BSI TR-03183-2 §5.2.1: who created the SBOM — the vendor of the application, who is also
	 * the creator of the application (the primary component). The tool that wrote it is listed
	 * as tool, not as creator. The vendor is named by the bnd project the {@code .bndrun} lives in
	 * ({@code Bundle-Vendor}, {@code Bundle-ContactAddress}, {@code Bundle-DocURL}); a
	 * {@code .bndrun} inherits only from the workspace, not from that project's {@code bnd.bnd},
	 * so the project is looked up. What the project leaves open comes from the {@code .bndrun}
	 * and the workspace. The {@code creator} option overrides email address and URL. Without
	 * that option derived only from level medium on, like the other fields of the TR.
	 */
	private SbomCreator creator() {
		// an explicit creator gets the vendor's name at every level
		boolean derive = config.creator() != null || config.level()
			.includes(SbomLevel.MEDIUM);
		SbomCreator host = derive ? Creators.fromProperties(hostProject()) : null;
		SbomCreator run = derive ? Creators.fromProperties(project) : null;
		String name = host != null && host.name() != null ? host.name() : run != null ? run.name() : null;
		if (config.creator() != null) {
			return Creators.fromOption(config.creator(), name);
		}
		SbomCreator reachable = host != null && host.isIdentified() ? host
			: run != null && run.isIdentified() ? run : null;
		return reachable != null ? SbomCreator.of(name, reachable.email(), reachable.url())
			: SbomCreator.of(name, null, null);
	}

	/**
	 * The bnd project whose directory holds the {@code .bndrun}, or {@code null} for a
	 * {@code .bndrun} elsewhere (or a project exported through its own {@code bnd.bnd}).
	 */
	private Project hostProject() {
		try {
			File file = project.getPropertiesFile();
			Workspace workspace = project.getWorkspace();
			if (file == null || workspace == null || Project.BNDFILE.equals(file.getName())) {
				return null;
			}
			File dir = file.getParentFile();
			if (dir == null || !new File(dir, Project.BNDFILE).isFile()) {
				return null;
			}
			Project host = workspace.getProject(dir.getName());
			return host != null && dir.getCanonicalFile()
				.equals(host.getBase()
					.getCanonicalFile()) ? host : null;
		} catch (Exception e) {
			project.warning("Could not determine the project of %s: %s", project.getPropertiesFile(), e);
			return null;
		}
	}

	/**
	 * BSI TR-03183-2 §8.1.4–§8.1.7: a jar holds Java code (executable), combines several
	 * components (archive) and keeps their metadata — entries, manifest (structured).
	 */
	private static void setJarProperties(SbomComponent component) {
		component.setFileProperties(true, true, true);
	}

	/** A jar embedded as a file in a bundle is a jar too; shaded classes are not a file. */
	private static void setEmbeddedJarProperties(SbomComponent embedded) {
		if (embedded.getFilename() != null && isJar(embedded.getFilename())) {
			setJarProperties(embedded);
		}
		for (SbomComponent nested : embedded.getEmbedded()) {
			setEmbeddedJarProperties(nested);
		}
	}

	private static boolean isJar(String filename) {
		return filename.toLowerCase(Locale.ROOT)
			.endsWith(".jar");
	}

	/** The creator of the Java SE standard (BSI TR-03183-2 §5.2.2): the body that specifies it. */
	static final SbomCreator JAVA_SE_CREATOR = SbomCreator.of("Java Community Process", null, "https://jcp.org");

	/**
	 * The Java SE platform as a logical component (BSI TR-03183-2 §3.2.2), or {@code null} when
	 * neither {@code -runee} nor any bundle names an execution environment.
	 * <p>
	 * It is not delivered: the operator chooses the runtime, of any vendor and in any version
	 * that implements the API. So the component stands for the Java SE API the application is
	 * written against, not for a runtime — without PURL or CPE, which would name one
	 * implementation. Its version is the minimum the application requires (§3.2.1):
	 * {@code -runee}, the environment the application was resolved — and so tested — against;
	 * without it the highest of the minimums the bundles require ({@code Require-Capability:
	 * osgi.ee}, {@code Bundle-RequiredExecutionEnvironment}).
	 * <p>
	 * Java SE is a standard, so its creator is the body that specifies it, the Java Community
	 * Process — not the vendor of whichever runtime the operator installs.
	 */
	SbomComponent javaRuntime() {
		EE ee = null;
		String runee = project.getProperty(Constants.RUNEE);
		if (runee != null && !runee.isBlank()) {
			EE parsed = EE.parse(runee.trim());
			if (parsed != null && parsed != EE.UNKNOWN) {
				ee = parsed;
			}
		}
		if (ee == null) {
			for (Manifest manifest : manifests.values()) {
				EE required = minimumEE(manifest);
				if (required != null && (ee == null || isHigher(required, ee))) {
					ee = required;
				}
			}
		}
		if (ee == null) {
			return null;
		}
		return new SbomComponent().setBsn(ee.getCapabilityName())
			.setVersion(ee.getCapabilityVersion()
				.toString())
			.setLogical(true)
			.setMinimumVersion(true)
			.setDescription("Java SE platform standard (osgi.ee=" + ee.getCapabilityName() + "), at least version "
				+ ee.getCapabilityVersion() + "; not delivered: the Java runtime implementing it is chosen by the "
				+ "operator")
			.setCreator(JAVA_SE_CREATOR)
			.setCategory(Category.FRAMEWORK);
	}

	/**
	 * The lowest execution environment a bundle accepts, or {@code null} when it requires none.
	 * Only environments of the Java SE line count; a bundle that names several accepts the
	 * lowest of them.
	 */
	static EE minimumEE(Manifest manifest) {
		if (manifest == null) {
			return null;
		}
		EE lowest = null;
		try {
			Parameters requirements = new Parameters(manifest.getMainAttributes()
				.getValue(Constants.REQUIRE_CAPABILITY));
			for (Map.Entry<String, Attrs> entry : requirements.entrySet()) {
				if (!"osgi.ee".equals(Processor.removeDuplicateMarker(entry.getKey()))) {
					continue;
				}
				String filter = entry.getValue()
					.get("filter:");
				if (filter == null) {
					continue;
				}
				Filter parsed = new Filter(filter);
				for (EE candidate : EE.values()) {
					if (isJavaSE(candidate) && (lowest == null || isHigher(lowest, candidate))
						&& parsed.matchMap(Map.of("osgi.ee", candidate.getCapabilityName(), "version",
							candidate.getCapabilityVersion()))) {
						lowest = candidate;
					}
				}
			}
			if (lowest == null) {
				String bree = manifest.getMainAttributes()
					.getValue(Constants.BUNDLE_REQUIREDEXECUTIONENVIRONMENT);
				for (String name : new Parameters(bree).keySet()) {
					EE candidate = EE.parse(name.trim());
					if (candidate != null && isJavaSE(candidate) && (lowest == null || isHigher(lowest, candidate))) {
						lowest = candidate;
					}
				}
			}
		} catch (Exception e) {
			// a malformed header or filter requires nothing we can name
			return lowest;
		}
		return lowest;
	}

	private static boolean isJavaSE(EE ee) {
		return ee != EE.UNKNOWN && "JavaSE".equals(ee.getCapabilityName());
	}

	private static boolean isHigher(EE a, EE b) {
		return a.getCapabilityVersion()
			.compareTo(b.getCapabilityVersion()) > 0;
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

	/**
	 * The application's version from the workspace's {@code Bundle-Version}. With a Maven group
	 * ({@code -groupid}) the workspace's artifacts are Maven artifacts, and their PURLs carry the
	 * Maven form of that version; the application follows, so that it matches its own
	 * components: {@code 0.1.1.SNAPSHOT} → {@code 0.1.1-SNAPSHOT}, as bnd writes it into a POM
	 * (major.minor.micro, then {@code -} and the qualifier). Without a group, or for a version
	 * that is not an OSGi version, the {@code Bundle-Version} as it is.
	 * <p>
	 * No PURL is derived for the application: it is not an artifact published under those
	 * coordinates, and a PURL would claim it is. {@code application.purl} sets one where there is
	 * such an artifact (an image, a distribution).
	 */
	static String applicationVersion(String group, String bundleVersion) {
		String version = firstOf(bundleVersion);
		if (version == null || group == null) {
			return version;
		}
		try {
			Version v = Version.parseVersion(version);
			String maven = v.getMajor() + "." + v.getMinor() + "." + v.getMicro();
			return v.getQualifier() != null && !v.getQualifier()
				.isEmpty() ? maven + "-" + v.getQualifier() : maven;
		} catch (IllegalArgumentException e) {
			return version;
		}
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
