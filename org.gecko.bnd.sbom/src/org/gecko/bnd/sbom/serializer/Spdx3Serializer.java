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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import org.gecko.bnd.sbom.SbomConfig;
import org.gecko.bnd.sbom.model.MavenCoordinates;
import org.gecko.bnd.sbom.model.SbomComponent;
import org.gecko.bnd.sbom.model.SbomComponent.Category;
import org.gecko.bnd.sbom.model.SbomCreator;
import org.gecko.bnd.sbom.model.SbomLicense;
import org.gecko.bnd.sbom.model.SbomModel;
import org.gecko.bnd.sbom.model.SbomRefs;
import org.gecko.bnd.sbom.model.SbomTool;

import aQute.bnd.osgi.EmbeddedResource;
import aQute.bnd.osgi.Resource;
import aQute.lib.json.JSONCodec;

/**
 * Serializes the {@link SbomModel} as SPDX 3.0.1 JSON-LD ({@code format=spdx, spdx.version=
 * 3.0.1}), the version BSI TR-03183-2 v2.1.0 asks for (§4). The mapping follows the TR's
 * tables 8–12:
 * <ul>
 * <li>creator of the SBOM: {@code CreationInfo.createdBy} → an {@code Organization} with an
 * {@code email} or {@code urlScheme} external identifier; the tools in {@code createdUsing}</li>
 * <li>each component a {@code software_Package} — name, {@code software_packageVersion},
 * {@code originatedBy} its creator (email, or a URL as {@code other}), the PURL as
 * {@code packageUrl} external identifier</li>
 * <li>the delivered file a {@code software_File} the package {@code hasDistributionArtifact}:
 * filename, SHA-512 in {@code verifiedUsing}, and the executable/archive/structured properties
 * in {@code software_additionalPurpose} ({@code executable}, {@code archive}, {@code container}
 * or else {@code firmware})</li>
 * <li>licences a {@code simplelicensing_LicenseExpression} the package
 * {@code hasConcludedLicense} (distribution licence) and {@code hasDeclaredLicense}</li>
 * <li>{@code contains}/{@code dependsOn} relationships with their {@code completeness}</li>
 * </ul>
 * Everything is in one {@code @graph}: the {@code SpdxDocument}, a {@code software_Sbom} whose
 * root is the application, and the elements. Element ids are IRIs under the document's
 * namespace, derived from the content like the SPDX 2.3 namespace (#12), so an unchanged
 * application yields an identical document.
 */
public final class Spdx3Serializer implements SbomSerializer {

	static final String				CONTEXT				= "https://spdx.org/rdf/3.0.1/spdx-context.jsonld";
	static final String				SPEC_VERSION		= "3.0.1";
	private static final String		CREATION_INFO		= "_:creationinfo";
	private static final String		NAMESPACE_BASE		= "https://spdx.org/spdxdocs/";
	/** the TR's note on {@code software_additionalPurpose} (table 9) */
	public static final String		BSI_PURPOSE_COMMENT	= "software_additionalPurpose field is used to indicate the "
		+ "properties of BSI TR-03183-2";
	private static final JSONCodec	CODEC				= new JSONCodec();

	@Override
	public String fileExtension() {
		return ".spdx.json";
	}

	@Override
	public Resource serialize(SbomModel model, SbomConfig config) throws Exception {
		String appName = model.getApplicationName() != null ? model.getApplicationName() : "application";
		SbomRefs refs = SbomRefs.of(model);
		Graph graph = new Graph(NAMESPACE_BASE + sanitize(appName) + "-" + SerialNumbers.of(model, refs, config) + "#",
			model.isDependenciesComplete());

		// TR table 8: who created the SBOM, and with which tools
		String sbomCreator = graph.agent(model.getCreator(), "urlScheme");
		List<Object> tools = new ArrayList<>();
		for (SbomTool tool : model.getTools()) {
			tools.add(graph.tool(tool.name() + (tool.version() != null ? "-" + tool.version() : "")));
		}
		if (tools.isEmpty()) {
			tools.add(graph.tool("org.gecko.bnd.sbom"));
		}

		// the application: the root of the SBOM (TR table 10), created by the SBOM's creator
		String application = graph.id(refs.spdxApplication());
		graph.add(application(application, model, sbomCreator));

		List<Object> contained = new ArrayList<>();
		for (SbomComponent component : model.getComponents()) {
			String id = graph.id(refs.spdxOf(component));
			addComponent(graph, refs, component, id);
			contained.add(id);
		}
		// the application contains its components; a bundle the libraries it embeds (#8)
		graph.relationship(application, "contains", contained, "complete");
		// #13: the dependency graph
		graph.dependsOn(application, model.getApplicationDependencies(), refs);
		for (SbomComponent component : model.getAllComponents()) {
			graph.dependsOn(graph.id(refs.spdxOf(component)), model.getDependencies(component), refs);
		}

		String sbomId = graph.id("SPDXRef-Sbom");
		Map<String, Object> sbom = Graph.newElement("software_Sbom", sbomId);
		sbom.put("rootElement", listOf(application));
		sbom.put("element", new ArrayList<>(graph.elementIds()));
		sbom.put("software_sbomType", listOf("build"));

		Map<String, Object> document = Graph.newElement("SpdxDocument", graph.id("SPDXRef-DOCUMENT"));
		document.put("name", appName);
		document.put("dataLicense", graph.licenseExpression("CC0-1.0"));
		document.put("profileConformance", List.of("core", "software", "simpleLicensing"));
		document.put("rootElement", listOf(sbomId));
		List<Object> all = new ArrayList<>(graph.elementIds());
		all.add(sbomId);
		document.put("element", all);
		// SPDX has no free properties: the build's own (property.<name>) go into the comment
		if (!model.getProperties()
			.isEmpty()) {
			List<String> lines = new ArrayList<>();
			model.getProperties()
				.forEach((name, value) -> lines.add(name + "=" + value));
			document.put("comment", String.join("\n", lines));
		}

		Map<String, Object> creationInfo = new LinkedHashMap<>();
		creationInfo.put("type", "CreationInfo");
		creationInfo.put("@id", CREATION_INFO);
		creationInfo.put("specVersion", SPEC_VERSION);
		creationInfo.put("created", config.created()
			.toString());
		creationInfo.put("createdBy", listOf(sbomCreator));
		creationInfo.put("createdUsing", tools);
		// A2.5/Q4: completeness and the known gaps
		StringBuilder comment = new StringBuilder(
			model.isDependenciesComplete() ? "Dependencies complete." : "Dependencies incomplete.");
		for (String unknown : model.getKnownUnknowns()) {
			comment.append(" Known unknown: ")
				.append(unknown)
				.append('.');
		}
		creationInfo.put("comment", comment.toString());

		List<Object> elements = new ArrayList<>();
		elements.add(creationInfo);
		elements.add(document);
		elements.add(sbom);
		elements.addAll(graph.elements);

		Map<String, Object> root = new LinkedHashMap<>();
		root.put("@context", CONTEXT);
		root.put("@graph", elements);
		String json = CODEC.enc()
			.indent("  ")
			.put(root)
			.toString();
		return new EmbeddedResource(json, config.created()
			.toEpochMilli());
	}

	private static Map<String, Object> application(String id, SbomModel model, String creator) {
		Map<String, Object> pkg = Graph.newElement("software_Package", id);
		pkg.put("name", model.getApplicationName() != null ? model.getApplicationName() : "application");
		if (model.getApplicationVersion() != null) {
			pkg.put("software_packageVersion", model.getApplicationVersion());
		}
		pkg.put("software_primaryPurpose", "application");
		// TR table 9: the creator of the primary component is the creator of the SBOM
		pkg.put("originatedBy", listOf(creator));
		pkg.put("suppliedBy", creator);
		if (model.getVcsUrl() != null) {
			pkg.put("software_sourceInfo", "git+" + model.getVcsUrl());
		}
		if (model.getWebsiteUrl() != null) {
			pkg.put("software_homePage", model.getWebsiteUrl());
		}
		if (model.getApplicationPurl() != null) {
			pkg.put("software_packageUrl", model.getApplicationPurl());
			pkg.put("externalIdentifier", listOf(externalIdentifier("packageUrl", model.getApplicationPurl())));
		}
		if (model.getApplicationGroup() != null) {
			pkg.put("comment", "Group: " + model.getApplicationGroup() + ".");
		}
		return pkg;
	}

	private void addComponent(Graph graph, SbomRefs refs, SbomComponent component, String id) {
		Map<String, Object> pkg = Graph.newElement("software_Package", id);
		// Name and version agree with the PURL: Maven coordinates when verified, otherwise the
		// OSGi identity (#14).
		MavenCoordinates maven = component.getMaven();
		if (maven != null) {
			pkg.put("name", maven.artifactId());
			pkg.put("software_packageVersion", maven.version());
		} else {
			pkg.put("name", component.getBsn());
			if (component.getVersion() != null) {
				pkg.put("software_packageVersion", component.getVersion());
			}
		}
		pkg.put("software_primaryPurpose", purpose(component));
		// TR table 9: the component creator; a URL is of type "other" there
		if (component.getCreator() != null) {
			pkg.put("originatedBy", listOf(graph.agent(component.getCreator(), "other")));
		}
		if (component.getDescription() != null) {
			pkg.put("description", component.getDescription());
		}
		// #9: the download URL the repository gave, if any
		if (component.getDistributionUrl() != null) {
			pkg.put("software_downloadLocation", component.getDistributionUrl());
		}
		if (component.getPurl() != null) {
			pkg.put("software_packageUrl", component.getPurl());
			// TR table 11: other unique identifiers
			pkg.put("externalIdentifier", listOf(externalIdentifier("packageUrl", component.getPurl())));
		}
		String comment = comment(component);
		if (comment != null) {
			pkg.put("comment", comment);
		}
		graph.add(pkg);

		// TR table 9: the deployable file — filename, hash and file properties
		if (component.getFilename() != null || component.getSha512() != null) {
			Map<String, Object> file = Graph.newElement("software_File", graph.id(refs.spdxOf(component) + "-file"));
			file.put("name", component.getFilename() != null ? component.getFilename() : pkg.get("name"));
			if (component.getSha512() != null) {
				Map<String, Object> hash = new LinkedHashMap<>();
				hash.put("type", "Hash");
				hash.put("algorithm", "sha512");
				hash.put("hashValue", component.getSha512());
				file.put("verifiedUsing", listOf(hash));
			}
			file.put("software_fileKind", "file");
			if (component.hasFileProperties()) {
				List<Object> purposes = new ArrayList<>();
				if (component.getExecutable()) {
					purposes.add("executable");
				}
				if (component.getArchive()) {
					purposes.add("archive");
				}
				purposes.add(component.getStructured() ? "container" : "firmware");
				file.put("software_additionalPurpose", purposes);
				file.put("comment", BSI_PURPOSE_COMMENT);
			}
			graph.add(file);
			graph.relationship(id, "hasDistributionArtifact", listOf(file.get("spdxId")), "complete");
		}

		// TR table 9 (distribution licence) and table 11 (original licence)
		String expression = licenseExpression(component, graph);
		if (expression != null) {
			String license = graph.licenseExpression(expression);
			graph.relationship(id, "hasConcludedLicense", listOf(license), "complete");
			graph.relationship(id, "hasDeclaredLicense", listOf(license), "complete");
		}

		// #8: the libraries embedded in a bundle
		List<Object> embedded = new ArrayList<>();
		for (SbomComponent child : component.getEmbedded()) {
			String childId = graph.id(refs.spdxOf(child));
			addComponent(graph, refs, child, childId);
			embedded.add(childId);
		}
		if (!embedded.isEmpty()) {
			graph.relationship(id, "contains", embedded, "complete");
		}
	}

	private static String purpose(SbomComponent component) {
		if (component.isLogical()) {
			return "platform";
		}
		return component.getCategory() == Category.FRAMEWORK ? "framework" : "library";
	}

	/** SPDX has no free properties: the OSGi facts go into the comment, as with SPDX 2.3. */
	private static String comment(SbomComponent component) {
		List<String> comment = new ArrayList<>();
		if (component.isLogical()) {
			// BSI TR-03183-2 §3.2.2: the Java platform, named by its osgi.ee capability
			comment.add("Logical component: OSGi execution environment " + component.getBsn() + ".");
		} else if (component.getBsn() != null) {
			comment.add("OSGi bundle: " + component.getBsn()
				+ (component.getVersion() != null ? " " + component.getVersion() : "") + ".");
		}
		if (component.isProvided()) {
			comment.add("Not delivered: provided by the user's environment.");
		}
		if (component.isMinimumVersion()) {
			comment.add("Version is the minimum the application requires, not a delivered file's.");
		}
		if (component.getLayer() != null) {
			comment.add("Layer: " + component.getLayer()
				.id() + ".");
		}
		if (component.isUnverifiedIdentity()) {
			comment.add("Identity unverified (reduced matchability): no reliable PURL.");
		}
		if (component.getIdentitySource() != null) {
			comment.add("Maven identity " + component.getIdentitySource() + ".");
		}
		if (component.getRepositoryName() != null) {
			comment.add("Repository: " + component.getRepositoryName()
				+ (component.getRepositoryKind() != null ? " (" + component.getRepositoryKind() + ")" : "") + ".");
		}
		if (component.getEmbeddedPath() != null) {
			comment.add("Embedded: " + component.getEmbeddedPath() + ".");
		}
		return comment.isEmpty() ? null : String.join(" ", comment);
	}

	/**
	 * The licences of a component as one SPDX expression, {@code null} without any: SPDX ids and
	 * expressions verbatim, free text as a {@code LicenseRef} to a
	 * {@code simplelicensing_SimpleLicensingText}; several joined with {@code AND} (the
	 * {@code Bundle-License} header does not encode AND/OR).
	 */
	private static String licenseExpression(SbomComponent component, Graph graph) {
		List<SbomLicense> licenses = component.getLicenses();
		if (licenses.isEmpty()) {
			return null;
		}
		if (licenses.size() == 1 && licenses.get(0)
			.isExpression()) {
			return licenses.get(0)
				.expression();
		}
		List<String> parts = new ArrayList<>();
		for (SbomLicense license : licenses) {
			parts.add(license.isSpdx() || license.isExpression() ? license.asOperand()
				: graph.licenseRef(license.name(), license.url()));
		}
		return String.join(" AND ", parts);
	}

	private static Map<String, Object> externalIdentifier(String type, String identifier) {
		Map<String, Object> external = new LinkedHashMap<>();
		external.put("type", "ExternalIdentifier");
		external.put("externalIdentifierType", type);
		external.put("identifier", identifier);
		return external;
	}

	/** Element ids and namespaces: letters, digits, '.' and '-'. */
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
	 * The elements of one document: ids under its namespace, agents and licence expressions
	 * de-duplicated, relationships numbered in the order they are added.
	 */
	private static final class Graph {

		private final String				namespace;
		private final String				dependencyCompleteness;
		final List<Map<String, Object>>		elements		= new ArrayList<>();
		private final Map<String, String>	agents			= new LinkedHashMap<>();
		private final Map<String, String>	expressions		= new LinkedHashMap<>();
		private final Map<String, String>	licenseRefs		= new LinkedHashMap<>();
		/** {@code simplelicensing_customIdToUri} of the expressions that use a LicenseRef */
		private final List<Object>			customIds		= new ArrayList<>();
		private int							relationships;

		Graph(String namespace, boolean dependenciesComplete) {
			this.namespace = namespace;
			// TR table 9: the completeness of the dependencies, as the model declares it
			this.dependencyCompleteness = dependenciesComplete ? "complete" : "incomplete";
		}

		String id(String local) {
			return namespace + local;
		}

		static Map<String, Object> newElement(String type, String id) {
			Map<String, Object> element = new LinkedHashMap<>();
			element.put("type", type);
			element.put("spdxId", id);
			element.put("creationInfo", CREATION_INFO);
			return element;
		}

		void add(Map<String, Object> element) {
			elements.add(element);
		}

		Set<String> elementIds() {
			Set<String> ids = new LinkedHashSet<>();
			for (Map<String, Object> element : elements) {
				ids.add((String) element.get("spdxId"));
			}
			return ids;
		}

		/**
		 * An {@code Organization} for a creator, one per distinct creator: its email address,
		 * or else its URL as {@code urlType} external identifier. Without any creator an
		 * organization named {@code NOASSERTION}, since {@code createdBy} needs an agent.
		 */
		String agent(SbomCreator creator, String urlType) {
			String name = creator != null && creator.name() != null ? creator.name() : "NOASSERTION";
			String email = creator != null ? creator.email() : null;
			String url = creator != null ? creator.url() : null;
			String key = name + "|" + email + "|" + (email == null ? url + "|" + urlType : "");
			String existing = agents.get(key);
			if (existing != null) {
				return existing;
			}
			String id = id("SPDXRef-Agent-" + (agents.size() + 1));
			agents.put(key, id);
			Map<String, Object> agent = newElement("Organization", id);
			agent.put("name", name);
			if (email != null) {
				agent.put("externalIdentifier", listOf(externalIdentifier("email", email)));
			} else if (url != null) {
				agent.put("externalIdentifier", listOf(externalIdentifier(urlType, url)));
			}
			elements.add(agent);
			return id;
		}

		String tool(String name) {
			String id = id("SPDXRef-Tool-" + sanitize(name));
			Map<String, Object> tool = newElement("Tool", id);
			tool.put("name", name);
			elements.add(tool);
			return id;
		}

		/** A {@code simplelicensing_LicenseExpression}, one per distinct expression. */
		String licenseExpression(String expression) {
			String existing = expressions.get(expression);
			if (existing != null) {
				return existing;
			}
			String id = id("SPDXRef-License-" + (expressions.size() + 1));
			expressions.put(expression, id);
			Map<String, Object> license = newElement("simplelicensing_LicenseExpression", id);
			license.put("simplelicensing_licenseExpression", expression);
			List<Object> used = new ArrayList<>();
			for (Object entry : customIds) {
				@SuppressWarnings("unchecked")
				Map<String, Object> dictionary = (Map<String, Object>) entry;
				if (Pattern.compile("\\b" + Pattern.quote((String) dictionary.get("key")) + "\\b")
					.matcher(expression)
					.find()) {
					used.add(dictionary);
				}
			}
			if (!used.isEmpty()) {
				license.put("simplelicensing_customIdToUri", used);
			}
			elements.add(license);
			return id;
		}

		/**
		 * A free-text licence without SPDX id: {@code LicenseRef-N}, declared as a
		 * {@code simplelicensing_SimpleLicensingText}; identical names share one.
		 */
		String licenseRef(String name, String url) {
			String existing = licenseRefs.get(name);
			if (existing != null) {
				return existing;
			}
			String ref = "LicenseRef-" + licenseRefs.size();
			licenseRefs.put(name, ref);
			String id = id("SPDXRef-" + ref);
			Map<String, Object> text = newElement("simplelicensing_SimpleLicensingText", id);
			text.put("name", name);
			// the text is required; only the declared name is known
			text.put("simplelicensing_licenseText", name);
			if (url != null) {
				text.put("comment", "See " + url + ".");
			}
			elements.add(text);
			Map<String, Object> entry = new LinkedHashMap<>();
			entry.put("type", "DictionaryEntry");
			entry.put("key", ref);
			entry.put("value", id);
			customIds.add(entry);
			return ref;
		}

		void relationship(String from, String type, List<Object> to, String completeness) {
			if (to.isEmpty()) {
				return;
			}
			Map<String, Object> relationship = newElement("Relationship",
				id("SPDXRef-Relationship-" + (++relationships)));
			relationship.put("from", from);
			relationship.put("relationshipType", type);
			relationship.put("to", to);
			relationship.put("completeness", completeness);
			elements.add(relationship);
		}

		void dependsOn(String from, Set<SbomComponent> targets, SbomRefs refs) {
			List<Object> to = new ArrayList<>();
			for (SbomComponent target : targets) {
				to.add(id(refs.spdxOf(target)));
			}
			relationship(from, "dependsOn", to, dependencyCompleteness);
		}
	}
}
