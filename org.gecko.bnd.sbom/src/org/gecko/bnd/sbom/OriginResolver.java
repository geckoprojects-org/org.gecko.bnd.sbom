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

import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.osgi.framework.namespace.IdentityNamespace;
import org.osgi.resource.Capability;
import org.osgi.resource.Requirement;
import org.osgi.service.repository.ContentNamespace;
import org.osgi.service.repository.Repository;

import aQute.bnd.build.Container;
import aQute.bnd.build.Container.TYPE;
import aQute.bnd.osgi.resource.CapReqBuilder;
import aQute.bnd.service.RepositoryPlugin;
import aQute.bnd.version.Version;

/**
 * Where a bundle was taken from (#9): the repository, its kind, and a download URL.
 * <p>
 * bnd does not record the repository on the {@link Container}. It asks the repositories in
 * order and takes the first that has the version; the same is done here. The kind is derived
 * from the repository implementation ({@code maven}, {@code p2}, {@code osgi} for an OSGi/OBR
 * index, {@code file} for local repositories). The download URL is the {@code osgi.content} URL
 * of the bundle, when the repository is an OSGi {@link Repository} and that URL is http(s);
 * otherwise the repository's location, when it is http(s) and not a Maven repository (a Maven
 * artifact has its PURL). Local file locations are not written: they say nothing outside the
 * build machine.
 */
public final class OriginResolver {

	/** Origin of a component; fields may be {@code null}. */
	public record Origin(String repositoryName, String kind, String distributionUrl) {}

	static final String					WORKSPACE	= "workspace";

	private static final Map<String, String>	KINDS		= Map.of(		//
		"MavenBndRepository", "maven",										//
		"P2Repository", "p2",												//
		"OSGiRepository", "osgi",											//
		"LocalIndexedRepo", "file",											//
		"FileRepo", "file",													//
		"IndexedRepo", "file",												//
		"WorkspaceRepository", WORKSPACE);

	private final List<RepositoryPlugin> repositories;

	public OriginResolver(List<RepositoryPlugin> repositories) {
		this.repositories = repositories;
	}

	public Origin resolve(Container container) {
		if (container.getType() == TYPE.PROJECT) {
			return new Origin(WORKSPACE, WORKSPACE, null);
		}
		if (container.getType() != TYPE.REPO) {
			return null;
		}
		String bsn = container.getBundleSymbolicName();
		Version version;
		try {
			version = Version.parseVersion(container.getVersion());
		} catch (IllegalArgumentException e) {
			return null;
		}
		for (RepositoryPlugin repository : repositories) {
			try {
				if (!repository.versions(bsn)
					.contains(version)) {
					continue;
				}
			} catch (Exception e) {
				continue;
			}
			String kind = kind(repository);
			String url = contentUrl(repository, bsn, version);
			if (url == null && !"maven".equals(kind)) {
				// a Maven artifact is identified by its PURL; its repository location is a list of
				// repository URLs, not the artifact's
				url = httpOrNull(repository.getLocation());
			}
			return new Origin(repository.getName(), kind, url);
		}
		return null;
	}

	static String kind(Object repository) {
		String simpleName = repository.getClass()
			.getSimpleName();
		return KINDS.getOrDefault(simpleName, simpleName.toLowerCase(Locale.ROOT));
	}

	private static String contentUrl(RepositoryPlugin repository, String bsn, Version version) {
		if (!(repository instanceof Repository osgi)) {
			return null;
		}
		try {
			Requirement identity = CapReqBuilder.createBundleRequirement(bsn, "[" + version + "," + version + "]")
				.buildSyntheticRequirement();
			Map<Requirement, Collection<Capability>> providers = osgi.findProviders(List.of(identity));
			for (Capability provider : providers.getOrDefault(identity, List.of())) {
				// p2 has features with the same id as bundles; only the bundle is the artifact
				if (!IdentityNamespace.TYPE_BUNDLE.equals(provider.getAttributes()
					.get(IdentityNamespace.CAPABILITY_TYPE_ATTRIBUTE))
					&& !IdentityNamespace.TYPE_FRAGMENT.equals(provider.getAttributes()
						.get(IdentityNamespace.CAPABILITY_TYPE_ATTRIBUTE))) {
					continue;
				}
				for (Capability content : provider.getResource()
					.getCapabilities(ContentNamespace.CONTENT_NAMESPACE)) {
					Object url = content.getAttributes()
						.get(ContentNamespace.CAPABILITY_URL_ATTRIBUTE);
					String http = url != null ? httpOrNull(url.toString()) : null;
					if (http != null) {
						return http;
					}
				}
			}
		} catch (Exception e) {
			// no URL then
		}
		return null;
	}

	private static String httpOrNull(String location) {
		if (location == null) {
			return null;
		}
		// a location may list several URLs; the first is the one tried first
		String trimmed = location.split(",")[0]
			.trim();
		String lower = trimmed.toLowerCase(Locale.ROOT);
		return lower.startsWith("https://") || lower.startsWith("http://") ? trimmed : null;
	}
}
