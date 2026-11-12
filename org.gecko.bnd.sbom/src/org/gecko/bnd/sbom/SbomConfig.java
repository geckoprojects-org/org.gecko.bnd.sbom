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

import java.util.Map;

import aQute.bnd.build.Project;
import org.gecko.bnd.sbom.model.SbomLevel;
import org.gecko.bnd.sbom.serializer.SbomFormat;
import aQute.bnd.header.Attrs;
import aQute.bnd.header.OSGiHeader;

/**
 * Resolved SBOM configuration. Source order (last wins):
 * <ol>
 * <li>defaults ({@code simple}, {@code cyclonedx}, {@code includeOSGIMetadata=false} — see
 * requirements Q7)</li>
 * <li>the {@code -sbom} instruction in the {@code .bndrun} (declarative marker + config, A2.6)</li>
 * <li>the {@code options} passed to the trigger (take precedence)</li>
 * </ol>
 */
public final class SbomConfig {

	/** Instruction/marker name (opt-in switch, see Q7 / A2.6). */
	public static final String	SBOM			= "-sbom";

	static final String			LEVEL			= "level";
	static final String			FORMAT			= "format";
	static final String			INCLUDE_OSGI	= "includeOSGIMetadata";
	static final String			TIMESTAMP		= "timestamp";

	private final SbomLevel		level;
	private final SbomFormat	format;
	private final boolean		includeOSGIMetadata;
	private final String		timestamp;

	private SbomConfig(SbomLevel level, SbomFormat format, boolean includeOSGIMetadata, String timestamp) {
		this.level = level;
		this.format = format;
		this.includeOSGIMetadata = includeOSGIMetadata;
		this.timestamp = timestamp;
	}

	/** Programmatic factory (for tests and the Maven/Gradle wrappers). */
	public static SbomConfig of(SbomLevel level, SbomFormat format, boolean includeOSGIMetadata, String timestamp) {
		return new SbomConfig(level, format, includeOSGIMetadata, timestamp);
	}

	public static SbomConfig from(Project project, Map<String, String> options) {
		Attrs sbom = OSGiHeader.parseProperties(project.getProperty(SBOM, ""));

		SbomLevel level = SbomLevel.parse(pick(options, sbom, LEVEL, SbomLevel.SIMPLE.id()));
		SbomFormat format = SbomFormat.parse(pick(options, sbom, FORMAT, SbomFormat.CYCLONEDX.id()));
		boolean includeOSGIMetadata = Boolean.parseBoolean(pick(options, sbom, INCLUDE_OSGI, "false"));
		// Overridable only for reproducible tests; otherwise the serializer stamps the time.
		String timestamp = pick(options, sbom, TIMESTAMP, null);

		return new SbomConfig(level, format, includeOSGIMetadata, timestamp);
	}

	private static String pick(Map<String, String> options, Attrs sbom, String key, String defaultValue) {
		String fromOptions = options.get(key);
		if (fromOptions != null) {
			return fromOptions;
		}
		return sbom.getOrDefault(key, defaultValue);
	}

	public SbomLevel level() {
		return level;
	}

	public SbomFormat format() {
		return format;
	}

	public boolean includeOSGIMetadata() {
		return includeOSGIMetadata;
	}

	/** Explicitly set timestamp, or {@code null} (then the serializer stamps {@code now}). */
	public String timestamp() {
		return timestamp;
	}
}
