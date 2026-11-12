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
package org.gecko.bnd.sbom.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Format-neutral SBOM component. Deliberately format-agnostic (no CycloneDX/SPDX type) so
 * that several serializers can consume the same record.
 * <p>
 * Field × level see requirements §7: {@code name}/{@code version}/{@code purl} from
 * {@code simple}; {@code sha512}/{@code license}/{@code filename} from {@code medium}.
 */
public final class SbomComponent {

	/** Attribution of a component (technical, not legal) — see §7 origin markers. */
	public enum Category {
		BUNDLE_AUTHOR,
		INTEGRATOR,
		FRAMEWORK
	}

	private String		bsn;
	private String		version;
	/** Package URL, e.g. {@code pkg:maven/group/artifact@version}; {@code null} if unresolvable (Q3). */
	private String		purl;
	/** Verified Maven identity; {@code null} if unresolvable (Q3). bsn/version stay the OSGi identity. */
	private MavenCoordinates	maven;
	private String				sha512;
	/** Licenses detected for this component (medium+); may be several (dual-licensing / multiple headers). */
	private final List<SbomLicense>	licenses	= new ArrayList<>();
	private String				filename;
	private String		supplier;
	private Category	category;
	/**
	 * {@code true} when no reliable PURL could be determined (non-Maven / OBR / p2) — list
	 * honestly as "reduced matchability" instead of inventing a PURL (Q3.b / Q4). A wrong
	 * PURL silently breaks the CVE link.
	 */
	private boolean		unverifiedIdentity;
	/** Where the Maven identity came from when it was not found in the bundle (#9: configured). */
	private String		identitySource;
	/** #9: the repository the bundle was taken from */
	private String		repositoryName;
	/** #9: kind of that repository: maven, p2, osgi, file, workspace, ... */
	private String		repositoryKind;
	/** #9: where the artifact can be downloaded (http/https only) */
	private String		distributionUrl;
	/** #8: libraries repackaged or embedded in this bundle */
	private final List<SbomComponent>	embedded	= new ArrayList<>();
	/** #8: for an embedded library, where in the bundle it was found */
	private String		embeddedPath;

	public String getBsn() {
		return bsn;
	}

	public SbomComponent setBsn(String bsn) {
		this.bsn = bsn;
		return this;
	}

	public String getVersion() {
		return version;
	}

	public SbomComponent setVersion(String version) {
		this.version = version;
		return this;
	}

	public String getPurl() {
		return purl;
	}

	public SbomComponent setPurl(String purl) {
		this.purl = purl;
		return this;
	}

	public String getSha512() {
		return sha512;
	}

	public SbomComponent setSha512(String sha512) {
		this.sha512 = sha512;
		return this;
	}

	public List<SbomLicense> getLicenses() {
		return licenses;
	}

	public SbomComponent addLicense(SbomLicense license) {
		licenses.add(license);
		return this;
	}

	public String getFilename() {
		return filename;
	}

	public SbomComponent setFilename(String filename) {
		this.filename = filename;
		return this;
	}

	public String getSupplier() {
		return supplier;
	}

	public SbomComponent setSupplier(String supplier) {
		this.supplier = supplier;
		return this;
	}

	public Category getCategory() {
		return category;
	}

	public SbomComponent setCategory(Category category) {
		this.category = category;
		return this;
	}

	public MavenCoordinates getMaven() {
		return maven;
	}

	public SbomComponent setMaven(MavenCoordinates maven) {
		this.maven = maven;
		return this;
	}

	public boolean isUnverifiedIdentity() {
		return unverifiedIdentity;
	}

	public SbomComponent setUnverifiedIdentity(boolean unverifiedIdentity) {
		this.unverifiedIdentity = unverifiedIdentity;
		return this;
	}

	public String getIdentitySource() {
		return identitySource;
	}

	public SbomComponent setIdentitySource(String identitySource) {
		this.identitySource = identitySource;
		return this;
	}

	public String getRepositoryName() {
		return repositoryName;
	}

	public SbomComponent setRepositoryName(String repositoryName) {
		this.repositoryName = repositoryName;
		return this;
	}

	public String getRepositoryKind() {
		return repositoryKind;
	}

	public SbomComponent setRepositoryKind(String repositoryKind) {
		this.repositoryKind = repositoryKind;
		return this;
	}

	public String getDistributionUrl() {
		return distributionUrl;
	}

	public SbomComponent setDistributionUrl(String distributionUrl) {
		this.distributionUrl = distributionUrl;
		return this;
	}

	public List<SbomComponent> getEmbedded() {
		return embedded;
	}

	public SbomComponent addEmbedded(SbomComponent component) {
		embedded.add(component);
		return this;
	}

	public String getEmbeddedPath() {
		return embeddedPath;
	}

	public SbomComponent setEmbeddedPath(String embeddedPath) {
		this.embeddedPath = embeddedPath;
		return this;
	}
}
