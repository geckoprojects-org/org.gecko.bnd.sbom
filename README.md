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

The same options can be set declaratively with the `-sbom` instruction in the `.bndrun`;
options passed on the command line take precedence.

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
