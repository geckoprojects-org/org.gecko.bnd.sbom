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

import java.io.ByteArrayOutputStream;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

import org.gecko.bnd.sbom.model.SbomComponent;
import org.gecko.bnd.sbom.model.SbomLevel;
import org.gecko.bnd.sbom.model.SbomModel;
import org.gecko.bnd.sbom.serializer.CycloneDxSerializer;
import org.gecko.bnd.sbom.serializer.SbomFormat;
import org.gecko.bnd.sbom.serializer.SpdxSerializer;
import org.junit.jupiter.api.Test;

import aQute.bnd.osgi.Resource;
import aQute.lib.json.JSONCodec;

/**
 * The dependency graph from the manifests of the resolved set (#13).
 */
public class DependencyGraphTest {

	private static final JSONCodec				CODEC		= new JSONCodec();

	private final Map<SbomComponent, Manifest>	manifests	= new LinkedHashMap<>();

	private SbomComponent bundle(String bsn, String... headers) {
		Manifest manifest = new Manifest();
		Attributes main = manifest.getMainAttributes();
		main.put(Attributes.Name.MANIFEST_VERSION, "1.0");
		main.putValue("Bundle-ManifestVersion", "2");
		main.putValue("Bundle-SymbolicName", bsn);
		main.putValue("Bundle-Version", "1.0.0");
		for (int i = 0; i < headers.length; i += 2) {
			main.putValue(headers[i], headers[i + 1]);
		}
		SbomComponent component = new SbomComponent().setBsn(bsn)
			.setVersion("1.0.0");
		manifests.put(component, manifest);
		return component;
	}

	@Test
	public void importPackageRequireBundleAndFragmentHost() {
		SbomComponent api = bundle("api", "Export-Package", "com.example.api;version=1.0");
		SbomComponent impl = bundle("impl", "Import-Package", "com.example.api;version=\"[1,2)\"");
		SbomComponent client = bundle("client", "Require-Bundle", "api");
		SbomComponent fragment = bundle("fragment", "Fragment-Host", "impl");

		Map<SbomComponent, Set<SbomComponent>> edges = new DependencyGraph(manifests).edges();

		assertThat(edges.get(impl)).containsExactly(api);
		assertThat(edges.get(client)).containsExactly(api);
		assertThat(edges.get(fragment)).containsExactly(impl);
		assertThat(edges.get(api)).isEmpty();
	}

	@Test
	public void substitutableExportIsNoEdge() {
		bundle("other", "Export-Package", "com.example.api;version=1.0");
		SbomComponent self = bundle("self", "Export-Package", "com.example.api;version=1.0", "Import-Package",
			"com.example.api;version=\"[1,2)\"");

		assertThat(new DependencyGraph(manifests).edges()
			.get(self)).isEmpty();
	}

	@Test
	public void highestVersionWinsAmongSeveralProviders() {
		bundle("old", "Export-Package", "com.example.api;version=1.0");
		SbomComponent newer = bundle("newer", "Export-Package", "com.example.api;version=1.5");
		SbomComponent consumer = bundle("consumer", "Import-Package", "com.example.api;version=\"[1,2)\"");

		assertThat(new DependencyGraph(manifests).edges()
			.get(consumer)).containsExactly(newer);
	}

	@Test
	public void versionRangeIsRespected() {
		SbomComponent v1 = bundle("v1", "Export-Package", "com.example.api;version=1.0");
		bundle("v2", "Export-Package", "com.example.api;version=2.0");
		SbomComponent consumer = bundle("consumer", "Import-Package", "com.example.api;version=\"[1,2)\"");

		assertThat(new DependencyGraph(manifests).edges()
			.get(consumer)).containsExactly(v1);
	}

	@Test
	public void optionalImportOnlyWithProvider() {
		SbomComponent api = bundle("api", "Export-Package", "com.example.api;version=1.0");
		SbomComponent consumer = bundle("consumer", "Import-Package",
			"com.example.api;resolution:=optional, com.example.missing;resolution:=optional");

		assertThat(new DependencyGraph(manifests).edges()
			.get(consumer)).containsExactly(api);
	}

	@Test
	public void eeDynamicImportAndActiveRequirementsAreNotWired() {
		bundle("api", "Export-Package", "com.example.api;version=1.0", "Provide-Capability",
			"osgi.service;objectClass:List<String>=com.example.Service");
		SbomComponent consumer = bundle("consumer", "DynamicImport-Package", "com.example.*", "Require-Capability",
			"osgi.ee;filter:=\"(&(osgi.ee=JavaSE)(version=17))\","
				+ "osgi.service;filter:=\"(objectClass=com.example.Service)\";effective:=active");

		assertThat(new DependencyGraph(manifests).edges()
			.get(consumer)).isEmpty();
	}

	@Test
	public void unprovidedPackagesAreSkipped() {
		SbomComponent consumer = bundle("consumer", "Import-Package", "javax.xml.parsers, org.w3c.dom");

		assertThat(new DependencyGraph(manifests).edges()
			.get(consumer)).isEmpty();
	}

	@Test
	public void rootsFromRunRequires() {
		SbomComponent api = bundle("api", "Export-Package", "com.example.api;version=1.0");
		SbomComponent app = bundle("app", "Import-Package", "com.example.api");

		DependencyGraph graph = new DependencyGraph(manifests);

		assertThat(graph.roots("bnd.identity;id='app'")).containsExactly(app);
		assertThat(graph.roots(null)).containsExactly(api, app);
		assertThat(graph.roots("bnd.identity;id='unknown'")).containsExactly(api, app);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void writtenToCycloneDxAndSpdx() throws Exception {
		SbomComponent api = bundle("api", "Export-Package", "com.example.api;version=1.0");
		SbomComponent app = bundle("app", "Import-Package", "com.example.api");
		SbomModel model = new SbomModel().setApplicationName("run.bndrun")
			.addComponent(api)
			.addComponent(app)
			.addDependency(app, api)
			.addApplicationDependency(app);

		Map<String, Object> bom = decode(new CycloneDxSerializer().serialize(model,
			SbomConfig.of(SbomLevel.SIMPLE, SbomFormat.CYCLONEDX, false, "2026-01-01T00:00:00Z")));
		assertThat((List<Object>) bom.get("dependencies")).containsExactly(
			Map.of("ref", "run.bndrun", "dependsOn", List.of("app@1.0.0")),
			Map.of("ref", "api@1.0.0", "dependsOn", List.of()),
			Map.of("ref", "app@1.0.0", "dependsOn", List.of("api@1.0.0")));

		Map<String, Object> doc = decode(new SpdxSerializer().serialize(model,
			SbomConfig.of(SbomLevel.SIMPLE, SbomFormat.SPDX, false, "2026-01-01T00:00:00Z")));
		assertThat((List<Object>) doc.get("relationships")).contains(
			Map.of("spdxElementId", "SPDXRef-run.bndrun", "relationshipType", "DEPENDS_ON", "relatedSpdxElement",
				"SPDXRef-app-1.0.0"),
			Map.of("spdxElementId", "SPDXRef-app-1.0.0", "relationshipType", "DEPENDS_ON", "relatedSpdxElement",
				"SPDXRef-api-1.0.0"));
	}

	@Test
	public void withoutGraphNoDependenciesSection() throws Exception {
		SbomModel model = new SbomModel().setApplicationName("run.bndrun")
			.addComponent(new SbomComponent().setBsn("c")
				.setVersion("1"));

		assertThat(decode(new CycloneDxSerializer().serialize(model,
			SbomConfig.of(SbomLevel.SIMPLE, SbomFormat.CYCLONEDX, false, "2026-01-01T00:00:00Z"))))
				.doesNotContainKey("dependencies");
	}

	@SuppressWarnings("unchecked")
	private static Map<String, Object> decode(Resource resource) throws Exception {
		try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
			resource.write(out);
			return CODEC.dec()
				.from(out.toString("UTF-8"))
				.get(Map.class);
		}
	}
}
