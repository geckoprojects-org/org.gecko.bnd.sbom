# org.gecko.bnd.sbom

A bnd exporter plugin that writes a Software Bill of Materials (SBOM) for the **resolved OSGi
application** of a `.bndrun`: the resolved `-runbundles` plus the framework layer (`-runfw`,
`-runpath`). Output formats are CycloneDX 1.6 and SPDX 2.3 (JSON).

| | |
|---|---|
| Maven coordinates | `org.geckoprojects.bnd.sbom:org.gecko.bnd.sbom` |
| Export type | `bnd.sbom` |
| Plugin class | `org.gecko.bnd.sbom.SbomExporter` |

## Usage

Register the plugin in the workspace (`cnf/build.bnd` or a file in `cnf/ext/`):

```
-plugin.sbom: org.gecko.bnd.sbom.SbomExporter;path:=<path to org.gecko.bnd.sbom.jar>
```

Export with the bnd CLI:

```
bnd export --exporter "bnd.sbom;level=medium;format=cyclonedx" app.bndrun
```

The SBOM is written to the project's `generated/` folder as `<name>.bndrun.cdx.json` or
`<name>.bndrun.spdx.json`.

| Option | Values | Default |
|---|---|---|
| `level` | `simple` (name, version, PURL), `medium` (adds hashes and licenses), `full` | `simple` |
| `format` | `cyclonedx`, `spdx` | `cyclonedx` |
| `includeOSGIMetadata` | `true`, `false` | `false` |
| `timestamp` | ISO-8601 instant, e.g. `2026-01-01T00:00:00Z`, for reproducible builds | time of the export |
| `serialNumber` | `content` (derived from format, level, application and components: an unchanged application keeps its serial number), `random` | `content` |
| `application.name`, `application.group`, `application.version` | identity of the application in the metadata | bndrun name, `-groupid`, `Bundle-Version` |
| `cyclonedx.version` | `1.6`, `1.7` (written with the matching `$schema`) | `1.6` |
| `application.purl` | PURL of the application, e.g. of the image built from the bndrun (`"pkg:oci/..."`, quoted); also its `bom-ref` | none |
| `property.<name>` | free properties of the BOM, e.g. `property.vcs:commit=${env;GITHUB_SHA}`; CycloneDX `metadata.properties`, SPDX document comment | none |
| `maven.<bsn>` | `groupId:artifactId[:version]`: Maven coordinates for a bundle from a p2 or OBR repository that is also published to Maven (version defaults to the bundle's major.minor.micro) | none |

### Configuration in the `.bndrun`

The options can be set declaratively in the `.bndrun` with the `-sbom` instruction. The
entries are separated by commas; semicolons are accepted as well. Invalid values (e.g. `level=mediun`)
are reported as errors and no SBOM is written; unknown options are reported as warnings.

```
-sbom: level=medium, format=spdx
```

`-sbom` only configures the exporter, it does not trigger it. The export still has to be
requested, and options passed there take precedence over `-sbom`:

```
bnd export --exporter bnd.sbom app.bndrun
bnd export --exporter "bnd.sbom;format=cyclonedx" app.bndrun
```

To make the SBOM the default export of the `.bndrun`, so that a plain `bnd export app.bndrun`
writes it, name the exporter in `-exporttype`. Here the options are attributes of the export
type and are separated by **semicolons**:

```
-exporttype: bnd.sbom;level=medium;format=spdx
```

A complete example:

```
-runfw: org.apache.felix.framework;version='[7.0.5,7.0.5]'
-runee: JavaSE-21
-runrequires: bnd.identity;id='my.application'
-runbundles: \
	my.application;version=snapshot,\
	org.apache.felix.scr;version='[2.2.6,2.2.7)'

-sbom: level=medium, format=cyclonedx
```

## What the SBOM contains

- **Resolved application:** the `-runbundles`, the framework (`-runfw`, `-runpath`) and the
  dependency graph between them, computed from the bundles' manifests.
- **Embedded libraries:** libraries a bundle carries inside — found through `pom.properties`
  of other artifacts (also under `OSGI-OPT/src`), jars on the `Bundle-ClassPath`, and, for
  bundles built in the same workspace, `-buildpath` entries whose classes were inlined with
  `-conditionalpackage`, `Private-Package` or `-includeresource @...`. They are listed as
  components of their own with their original Maven coordinates, so scanners match CVEs
  against them; `osgi:embedded:in` names the bundle.
- **Origin:** for every bundle the repository it was taken from (`osgi:repository:name`,
  `osgi:repository:kind`: `maven`, `p2`, `osgi`, `file`, `workspace`) and, where the
  repository knows it, the download URL as `distribution` reference.

## Build

Requires Java 21. The workspace uses bnd 7.4.0 and Gradle 9 (wrapper included).

```
./gradlew build
```

## Release

Publishing is done by Jenkins (`Jenkinsfile`); GitHub Actions only builds and tests.

| Branch | Result |
|---|---|
| `snapshot` | `-SNAPSHOT` bundles to the DIM Nexus (`dim-snapshot`) and the Central Portal snapshot repository |
| `main` | release bundles to the DIM Nexus (`dim-release`) and, signed, to Maven Central |
| any other | build and test |

The mechanics are in `cnf/ext/release.bnd`.

## License

Eclipse Public License 2.0, see `LICENSE`.
