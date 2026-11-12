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

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.gecko.bnd.sbom.model.MavenCoordinates;
import org.gecko.bnd.sbom.model.SbomLevel;
import org.gecko.bnd.sbom.serializer.SbomFormat;

import aQute.bnd.build.Project;
import aQute.bnd.header.Attrs;
import aQute.bnd.header.OSGiHeader;
import aQute.bnd.version.Version;
import aQute.service.reporter.Reporter;

/**
 * Resolved SBOM configuration. Source order (last wins):
 * <ol>
 * <li>defaults ({@code simple}, {@code cyclonedx}, {@code includeOSGIMetadata=false} — see
 * requirements Q7)</li>
 * <li>the {@code -sbom} instruction in the {@code .bndrun} (declarative marker + config, A2.6)</li>
 * <li>the {@code options} passed to the trigger (take precedence)</li>
 * </ol>
 * Invalid values are reported as errors on the given {@link Reporter} (the export then produces
 * no file); unknown keys as warnings, so that a newer {@code -sbom} does not break an older
 * exporter.
 */
public final class SbomConfig {

	/** Instruction/marker name (opt-in switch, see Q7 / A2.6). */
	public static final String	SBOM			= "-sbom";

	static final String			LEVEL			= "level";
	static final String			FORMAT			= "format";
	static final String			INCLUDE_OSGI	= "includeOSGIMetadata";
	static final String			TIMESTAMP		= "timestamp";
	static final String			SERIAL_NUMBER	= "serialNumber";
	/** Overrides of the application's identity (default: bndrun name, -groupid, Bundle-Version). */
	/** CycloneDX specification version of the output. */
	static final String			CYCLONEDX_VERSION	= "cyclonedx.version";
	/** Supported CycloneDX versions; the first is the default. */
	public static final List<String>	CYCLONEDX_VERSIONS	= List.of("1.6", "1.7");
	static final String			APP_NAME		= "application.name";
	static final String			APP_GROUP		= "application.group";
	static final String			APP_VERSION		= "application.version";
	/** PURL of the application, e.g. of the image or executable built from the bndrun. */
	static final String			APP_PURL		= "application.purl";
	/** {@code property.<name>=<value>}: free properties of the BOM (commit, image reference). */
	static final String			PROPERTY_PREFIX	= "property.";
	/**
	 * {@code maven.<bsn>=groupId:artifactId[:version]}: Maven coordinates of a bundle that has none
	 * in its repository or jar (p2, OBR), for bundles that are also published to Maven (#9).
	 */
	static final String			MAVEN_PREFIX	= "maven.";
	/** {@code serialNumber} derived from the BOM's content (default). */
	static final String			SERIAL_CONTENT	= "content";
	/** {@code serialNumber} random per export. */
	static final String			SERIAL_RANDOM	= "random";

	private static final List<String>	KEYS	= List.of(LEVEL, FORMAT, INCLUDE_OSGI, TIMESTAMP, SERIAL_NUMBER, APP_NAME,
		APP_GROUP, APP_VERSION, APP_PURL, CYCLONEDX_VERSION);

	private final SbomLevel		level;
	private final SbomFormat	format;
	private final boolean		includeOSGIMetadata;
	private final Instant		created;
	private final boolean		randomSerialNumber;
	private final String		applicationName;
	private final String		applicationGroup;
	private final String		applicationVersion;
	private final String		cyclonedxVersion;
	private final String		applicationPurl;
	private final Map<String, String>	properties;
	private final Map<String, String>	mavenMappings;

	private SbomConfig(SbomLevel level, SbomFormat format, boolean includeOSGIMetadata, Instant created,
		boolean randomSerialNumber, String applicationName, String applicationGroup, String applicationVersion,
		String cyclonedxVersion, String applicationPurl, Map<String, String> properties,
		Map<String, String> mavenMappings) {
		this.level = level;
		this.format = format;
		this.includeOSGIMetadata = includeOSGIMetadata;
		// SPDX requires whole seconds; CycloneDX gets the same instant
		this.created = created.truncatedTo(ChronoUnit.SECONDS);
		this.randomSerialNumber = randomSerialNumber;
		this.applicationName = applicationName;
		this.applicationGroup = applicationGroup;
		this.applicationVersion = applicationVersion;
		this.cyclonedxVersion = cyclonedxVersion;
		this.applicationPurl = applicationPurl;
		this.properties = Collections.unmodifiableMap(new LinkedHashMap<>(properties));
		this.mavenMappings = Collections.unmodifiableMap(new LinkedHashMap<>(mavenMappings));
	}

	/**
	 * Programmatic factory (for tests and the Maven/Gradle wrappers).
	 *
	 * @param timestamp ISO-8601 instant, or {@code null} for now
	 */
	public static SbomConfig of(SbomLevel level, SbomFormat format, boolean includeOSGIMetadata, String timestamp) {
		return new SbomConfig(level, format, includeOSGIMetadata,
			timestamp != null ? Instant.parse(timestamp) : Instant.now(), false, null, null, null,
			CYCLONEDX_VERSIONS.get(0), null, Map.of(), Map.of());
	}

	public static SbomConfig from(Project project, Map<String, String> options) {
		return from(project, project.getProperty(SBOM, ""), options);
	}

	/** Testable core of {@link #from(Project, Map)}: the {@code -sbom} value is passed in. */
	static SbomConfig from(Reporter reporter, String instruction, Map<String, String> options) {
		Map<String, String> values = new LinkedHashMap<>(parseInstruction(reporter, instruction));
		if (options != null) {
			values.putAll(options);
		}
		Map<String, String> properties = new LinkedHashMap<>();
		Map<String, String> mavenMappings = new LinkedHashMap<>();
		for (Map.Entry<String, String> entry : values.entrySet()) {
			String key = entry.getKey();
			if (key.startsWith(PROPERTY_PREFIX)) {
				String name = key.substring(PROPERTY_PREFIX.length());
				if (name.isBlank()) {
					reporter.error("SBOM option '%s' needs a property name, e.g. '%sgit:commit=...'", key, PROPERTY_PREFIX);
				} else {
					properties.put(name, entry.getValue());
				}
				continue;
			}
			if (key.startsWith(MAVEN_PREFIX)) {
				String bsn = key.substring(MAVEN_PREFIX.length());
				String value = entry.getValue() == null ? "" : entry.getValue()
					.trim();
				if (bsn.isBlank() || !value.matches("[^:\\s]+:[^:\\s]+(:[^:\\s]+)?")) {
					reporter.error(
						"Invalid SBOM option '%s=%s'; expected '%s<bundle symbolic name>=groupId:artifactId[:version]'",
						key, value, MAVEN_PREFIX);
				} else {
					mavenMappings.put(bsn, value);
				}
				continue;
			}
			if (!KEYS.contains(key)) {
				reporter.warning("Unknown SBOM option '%s' (in %s or the export options) is ignored; known options: %s",
					key, SBOM, String.join(", ", KEYS));
			}
		}

		SbomLevel level = value(reporter, values, LEVEL, SbomLevel.SIMPLE, SbomLevel::find,
			Arrays.stream(SbomLevel.values())
				.map(SbomLevel::id));
		SbomFormat format = value(reporter, values, FORMAT, SbomFormat.CYCLONEDX, SbomFormat::find,
			Arrays.stream(SbomFormat.values())
				.map(SbomFormat::id));
		Boolean includeOSGIMetadata = value(reporter, values, INCLUDE_OSGI, Boolean.FALSE, SbomConfig::parseBoolean,
			Stream.of("true", "false"));
		// Overridable for reproducible builds; otherwise the time of the export.
		Instant created = value(reporter, values, TIMESTAMP, null, SbomConfig::parseInstant,
			Stream.of("an ISO-8601 instant such as 2026-01-01T00:00:00Z"));

		String serialNumber = value(reporter, values, SERIAL_NUMBER, SERIAL_CONTENT, SbomConfig::parseSerialNumber,
			Stream.of(SERIAL_CONTENT, SERIAL_RANDOM));

		// a PURL must at least look like one; a wrong identity silently breaks matching
		String applicationPurl = value(reporter, values, APP_PURL, null,
			v -> v.startsWith("pkg:") && v.indexOf('/') > 4 ? Optional.of(v) : Optional.empty(),
			Stream.of("a package URL such as pkg:oci/weather@sha256%3A..."));

		String cyclonedxVersion = value(reporter, values, CYCLONEDX_VERSION, CYCLONEDX_VERSIONS.get(0),
			v -> CYCLONEDX_VERSIONS.contains(v) ? Optional.of(v) : Optional.empty(), CYCLONEDX_VERSIONS.stream());

		return new SbomConfig(level, format, includeOSGIMetadata, created != null ? created : Instant.now(),
			SERIAL_RANDOM.equals(serialNumber), text(values, APP_NAME), text(values, APP_GROUP),
			text(values, APP_VERSION), cyclonedxVersion, applicationPurl, properties, mavenMappings);
	}

	/**
	 * {@code -sbom} is a property list, whose entries bnd separates with commas. Semicolons are
	 * accepted as well, because that is how the same options are written as attributes of
	 * {@code -exporttype: bnd.sbom;level=medium}. None of the values can contain a semicolon.
	 */
	private static Attrs parseInstruction(Reporter reporter, String instruction) {
		if (instruction == null || instruction.isBlank()) {
			return new Attrs();
		}
		String normalized = instruction.replace(';', ',');
		try {
			return OSGiHeader.parseProperties(normalized);
		} catch (IllegalArgumentException e) {
			reporter.error("Invalid %s instruction '%s': expected key=value entries separated by commas, e.g. "
				+ "'%s: level=medium, format=spdx'", SBOM, instruction, SBOM);
			return new Attrs();
		}
	}

	private static <T> T value(Reporter reporter, Map<String, String> values, String key, T defaultValue,
		Function<String, Optional<T>> parser, Stream<String> allowed) {
		String raw = values.get(key);
		if (raw == null) {
			return defaultValue;
		}
		Optional<T> parsed = parser.apply(raw.trim());
		if (parsed.isEmpty()) {
			reporter.error("Invalid value '%s' for SBOM option '%s'; expected %s", raw, key,
				allowed.collect(Collectors.joining(", ")));
			return defaultValue;
		}
		return parsed.get();
	}

	private static Optional<Boolean> parseBoolean(String value) {
		if ("true".equalsIgnoreCase(value)) {
			return Optional.of(Boolean.TRUE);
		}
		if ("false".equalsIgnoreCase(value)) {
			return Optional.of(Boolean.FALSE);
		}
		return Optional.empty();
	}

	private static String text(Map<String, String> values, String key) {
		String value = values.get(key);
		return value == null || value.isBlank() ? null : value.trim();
	}

	private static Optional<String> parseSerialNumber(String value) {
		String lower = value.toLowerCase(Locale.ROOT);
		return SERIAL_CONTENT.equals(lower) || SERIAL_RANDOM.equals(lower) ? Optional.of(lower) : Optional.empty();
	}

	private static Optional<Instant> parseInstant(String value) {
		try {
			return Optional.of(Instant.parse(value));
		} catch (DateTimeParseException e) {
			return Optional.empty();
		}
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

	/**
	 * Creation time of the SBOM: the {@code timestamp} option, or the time the configuration was
	 * resolved. Used for the document's timestamp and for the file's modification time.
	 */
	public Instant created() {
		return created;
	}

	/**
	 * {@code true}: a random serial number per export ({@code serialNumber=random}); otherwise
	 * it is derived from the BOM's content, so an unchanged application yields the same one.
	 */
	public boolean randomSerialNumber() {
		return randomSerialNumber;
	}

	/** {@code application.purl} from {@code -sbom} or the options, or {@code null}. */
	public String applicationPurl() {
		return applicationPurl;
	}

	/**
	 * Configured Maven coordinates for a bundle ({@code maven.<bsn>}), or {@code null}. Without a
	 * version in the mapping the bundle's major.minor.micro is used.
	 */
	public MavenCoordinates mavenMapping(String bsn, String bundleVersion) {
		String value = mavenMappings.get(bsn);
		if (value == null) {
			return null;
		}
		String[] parts = value.split(":");
		String version = parts.length > 2 ? parts[2] : baseVersion(bundleVersion);
		return MavenCoordinates.of(parts[0], parts[1], version, null, null);
	}

	private static String baseVersion(String bundleVersion) {
		if (bundleVersion == null) {
			return null;
		}
		try {
			Version v = Version.parseVersion(bundleVersion);
			return v.getMajor() + "." + v.getMinor() + "." + v.getMicro();
		} catch (IllegalArgumentException e) {
			return null;
		}
	}

	/** The {@code property.<name>} entries by name, in the order given. */
	public Map<String, String> properties() {
		return properties;
	}

	/** CycloneDX specification version to write ({@code cyclonedx.version}), default 1.6. */
	public String cyclonedxVersion() {
		return cyclonedxVersion;
	}

	/** A copy writing the given CycloneDX version (for tests and the Maven/Gradle wrappers). */
	public SbomConfig withCyclonedxVersion(String version) {
		if (!CYCLONEDX_VERSIONS.contains(version)) {
			throw new IllegalArgumentException("Unsupported CycloneDX version " + version + ", supported: " + CYCLONEDX_VERSIONS);
		}
		return new SbomConfig(level, format, includeOSGIMetadata, created, randomSerialNumber, applicationName,
			applicationGroup, applicationVersion, version, applicationPurl, properties, mavenMappings);
	}

	/** {@code application.name} from {@code -sbom} or the options, or {@code null}. */
	public String applicationName() {
		return applicationName;
	}

	/** {@code application.group} from {@code -sbom} or the options, or {@code null}. */
	public String applicationGroup() {
		return applicationGroup;
	}

	/** {@code application.version} from {@code -sbom} or the options, or {@code null}. */
	public String applicationVersion() {
		return applicationVersion;
	}

	/** A copy with a random serial number (for tests and the Maven/Gradle wrappers). */
	public SbomConfig withRandomSerialNumber() {
		return new SbomConfig(level, format, includeOSGIMetadata, created, true, applicationName, applicationGroup,
			applicationVersion, cyclonedxVersion, applicationPurl, properties, mavenMappings);
	}
}
