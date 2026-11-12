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

import java.util.AbstractMap.SimpleEntry;
import java.util.Collection;
import java.util.Map;
import java.util.Map.Entry;

import aQute.bnd.annotation.plugin.BndPlugin;
import aQute.bnd.build.Container;
import aQute.bnd.build.Project;
import org.gecko.bnd.sbom.model.SbomModel;
import org.gecko.bnd.sbom.serializer.SbomSerializer;
import org.gecko.bnd.sbom.serializer.SbomSerializers;
import aQute.bnd.osgi.Resource;
import aQute.bnd.service.export.Exporter;

/**
 * View 2 (resolved application): produces an SBOM of the application from a resolved
 * {@code .bndrun}. Entry point per the bnd exporter SPI
 * ({@link aQute.bnd.service.export.Exporter}); invoked via
 * {@code bnd export --exporter bnd.sbom app.bndrun} (opt-in, explicit trigger — see
 * requirements/anforderungen-sbom-schichten.md §8.3).
 * <p>
 * Pipeline: {@code Project} (resolved .bndrun) → format-neutral {@link SbomModel} →
 * {@link SbomSerializer} (default: CycloneDX).
 */
@BndPlugin(name = "SBOM Exporter")
public class SbomExporter implements Exporter {

	/** Export type this exporter answers to ({@code bnd export --exporter bnd.sbom}). */
	public static final String TYPE = "bnd.sbom";

	@Override
	public String[] getTypes() {
		return new String[] {
			TYPE
		};
	}

	@Override
	public Entry<String, Resource> export(String type, Project project, Map<String, String> options)
		throws Exception {

		project.prepare();

		// Configuration: trigger options take precedence, then the -sbom instruction.
		SbomConfig config = SbomConfig.from(project, options);

		// View 2, A2.1: resolved -runbundles set with exact versions.
		Collection<Container> runbundles = project.getRunbundles();

		// The builder adds the framework layer itself (A2.2, currently -runfw + -runpath) and
		// resolves each component's PURL (Q3) and license.
		SbomModel model = new SbomModelBuilder(project, config).withRunbundles(runbundles)
			.build();

		SbomSerializer serializer = SbomSerializers.forFormat(config.format());
		Resource resource = serializer.serialize(model, config);

		String name = project.getName() + serializer.fileExtension();
		return new SimpleEntry<>(name, resource);
	}
}
