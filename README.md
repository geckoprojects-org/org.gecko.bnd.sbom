# org.gecko.bnd.sbom

[![CI Build](https://github.com/geckoprojects-org/org.gecko.bnd.sbom/actions/workflows/build.yml/badge.svg?branch=snapshot)](https://github.com/geckoprojects-org/org.gecko.bnd.sbom/actions/workflows/build.yml?query=branch%3Asnapshot)
[![CodeQL](https://github.com/geckoprojects-org/org.gecko.bnd.sbom/actions/workflows/codeql.yml/badge.svg?branch=snapshot)](https://github.com/geckoprojects-org/org.gecko.bnd.sbom/actions/workflows/codeql.yml?query=branch%3Asnapshot)
[![SBOM and Trivy](https://github.com/geckoprojects-org/org.gecko.bnd.sbom/actions/workflows/sbom.yml/badge.svg?branch=snapshot)](https://github.com/geckoprojects-org/org.gecko.bnd.sbom/actions/workflows/sbom.yml?query=branch%3Asnapshot)
[![Snapshot](https://img.shields.io/maven-metadata/v?metadataUrl=https%3A%2F%2Fcentral.sonatype.com%2Frepository%2Fmaven-snapshots%2Forg%2Fgeckoprojects%2Fbnd%2Forg.gecko.bnd.sbom%2Fmaven-metadata.xml&label=snapshot)](https://central.sonatype.com/repository/maven-snapshots/org/geckoprojects/bnd/org.gecko.bnd.sbom/)
[![Java 21](https://img.shields.io/badge/Java-21-blue.svg)](https://adoptium.net/)
[![License: EPL-2.0](https://img.shields.io/badge/License-EPL--2.0-blue.svg)](LICENSE)

SBOMs and dependency updates for OSGi applications built with [bnd](https://bnd.bndtools.org/).

- **SBOM exporter**: a bnd exporter plugin that writes a Software Bill of Materials of the
  **resolved OSGi application** of a `.bndrun`: the `-runbundles`, the framework underneath
  (`-runfw`, `-runpath`), the libraries embedded in bundles and the dependencies between them.
  CycloneDX 1.6/1.7 or SPDX 2.3/3.0.1, with the fields of BSI TR-03183-2 and the EU Cyber
  Resilience Act.
- **bnd update**: finds newer versions and vulnerability fixes for the libraries of a bnd
  workspace, within a version policy; applies them and proves them by resolving every bndrun and
  building the workspace; opens one pull or merge request a week. As command line, Gradle and
  Maven plugins, GitHub Action, and CI adapter for Jenkins and GitLab CI.

```
.bndrun ──► SBOM exporter ──► app.bndrun.cdx.json ──► Trivy ──► bnd update ──► fix versions, update pull request
```

## Documentation

**[Start here: docs/README.md](docs/README.md)**

| | |
|---|---|
| SBOM exporter | [reference: options, content, BSI TR-03183-2](docs/sbom-exporter.md) · [Gradle](docs/sbom-gradle.md) · [Maven](docs/sbom-maven.md) · [CI](docs/sbom-ci.md) |
| bnd update | [concepts, version policy, CLI](docs/bnd-update.md) · [Gradle](docs/bnd-update-gradle.md) · [Maven](docs/bnd-update-maven.md) · [CI: GitHub, GitLab, Jenkins](docs/bnd-update-ci.md) |
| Background | [Maven scopes in bnd-generated POMs](docs/maven-scopes.md) |
| Examples | [Gradle workspace, Maven project, Jenkinsfiles](examples/README.md) |
| Contributing | [build, CI, release](docs/development.md) |

## Quick start

### SBOM of a bndrun

```
# in the .bndrun
-plugin.sbom: org.gecko.bnd.sbom.SbomExporter;path:="${workspace}/cnf/cache/sbom-exporter/org.gecko.bnd.sbom.jar"
-sbom: level=medium, format=cyclonedx, validate=bsi-tr-03183-2
```

```
bnd export --exporter bnd.sbom app.bndrun          # writes app.bndrun.cdx.json
```

With Gradle: an `aQute.bnd.gradle.Export` task with `exporter = 'bnd.sbom'`
([how](docs/sbom-gradle.md)); with Maven: `bnd-export-maven-plugin` with
`<exporter>bnd.sbom</exporter>` ([how](docs/sbom-maven.md)).

### Updates and fixes

```
java -jar org.gecko.bnd.update.cli.jar updates
trivy sbom --format json --output trivy.json app.bndrun.cdx.json
java -jar org.gecko.bnd.update.cli.jar vulnerabilities --trivy trivy.json --sbom app.bndrun.cdx.json
java -jar org.gecko.bnd.update.cli.jar apply --mode each --build-command "./gradlew build -x test"
```

Weekly pull requests on GitHub:

```yaml
- run: ./gradlew assemble
- uses: geckoprojects-org/org.gecko.bnd.sbom/.github/actions/bnd-update@<sha>
  with:
    mode: each
    build-command: ./gradlew build -x test --no-daemon
```

For GitLab CI and Jenkins see [bnd update in CI](docs/bnd-update-ci.md).

## Artifacts

| Artifact | Maven coordinates |
|---|---|
| SBOM exporter | `org.geckoprojects.bnd:org.gecko.bnd.sbom` |
| bnd update library | `org.geckoprojects.bnd:org.gecko.bnd.update` |
| bnd update CLI | `org.geckoprojects.bnd:org.gecko.bnd.update.cli` |
| Gradle plugin | plugin id `org.geckoprojects.bnd.update` (Maven Central) |
| Maven plugin | `org.geckoprojects.bnd:bnd-update-maven-plugin` |

Until the first release: `0.1.0-SNAPSHOT` in the Central Portal's snapshot repository
(`https://central.sonatype.com/repository/maven-snapshots/`). Java 21 is required.

## License

Eclipse Public License 2.0, see [LICENSE](LICENSE).
