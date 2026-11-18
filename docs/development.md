# Developing org.gecko.bnd.sbom

This page is for contributors: how the repository is built, tested and released. Users of the
tools find everything in the [documentation](README.md).

## Layout

| Directory | What | Built with |
|---|---|---|
| `org.gecko.bnd.sbom/` | the SBOM exporter (bnd plugin) | bnd workspace (Gradle) |
| `org.gecko.bnd.update/` | bnd update, the library | bnd workspace (Gradle) |
| `org.gecko.bnd.update.cli/` | bnd update, the executable jar | bnd workspace (Gradle) |
| `maven-plugin/` | `bnd-update-maven-plugin` | Maven, against the jar of `org.gecko.bnd.update` |
| `gradle-plugin/` | the Gradle plugin `org.geckoprojects.bnd.update` | Gradle (`./gradlew -p gradle-plugin build`) |
| `.github/actions/bnd-update/` | the GitHub Action | composite action |
| `ci/` | the CI adapter `bnd-update.sh`, the GitLab template, the Jenkins example, `publish-plugins.sh` | bash |
| `examples/` | runnable examples, built by CI | Gradle, Maven |
| `docs/` | the documentation | Markdown |

## Build

Requires Java 21. The workspace uses bnd 7.5.0 (`bnd_version` in `gradle.properties`) and
Gradle 9 (wrapper included).

```
./gradlew build                                  # the bnd workspace, with tests
./gradlew -p gradle-plugin build                 # the Gradle plugin
mvn -f maven-plugin/pom.xml install              # the Maven plugin (needs org.gecko.bnd.update installed)
./gradlew :org.gecko.bnd.sbom:sbom               # the SBOM of the exporter's own runtime
```

The examples run against the jars of the same commit:

```
cd examples/gradle-workspace
../../gradlew sbom bndVulnerabilities -PtrivyReport=trivy-sample.json \
    -PsbomExporterJar=../../org.gecko.bnd.sbom/generated/org.gecko.bnd.sbom.jar \
    -PbndUpdateCli=../../org.gecko.bnd.update.cli/generated/org.gecko.bnd.update.cli.jar \
    -PlocalPlugins=true
```

## CI

| Workflow | Runs | Does |
|---|---|---|
| `build.yml` (CI Build) | pushes to `snapshot`/`main`, pull requests | licence headers, workspace build and tests, Maven plugin and example, Gradle plugin and example |
| `sbom.yml` (SBOM and Trivy) | pushes, pull requests, daily | SBOMs of the exporter's own runtime in every format, schema validation, Trivy, bnd update report |
| `codeql.yml` | pushes, pull requests, weekly | CodeQL `security-extended` |
| `bnd-update.yml` | weekly; pull requests that change the action or the tool | dependency updates of this workspace with bnd update itself |

All actions are pinned by commit SHA. The Gradle wrapper and the Python packages of the schema
check are verified by SHA-256.

## Release

Publishing is done by Jenkins (`Jenkinsfile`); GitHub Actions only builds and tests.

| Branch | Result |
|---|---|
| `snapshot` | `-SNAPSHOT` bundles and plugins to the DIM Nexus (`dim-snapshot`) and the Central Portal snapshot repository |
| `main` | release bundles and plugins to the DIM Nexus (`dim-release`) and, signed, to Maven Central |
| any other | build and test |

The mechanics are in `cnf/ext/release.bnd`.

## Publishing the Maven and Gradle plugins

The Maven and Gradle plugins are built outside the bnd workspace, but Jenkins publishes them
together with the bundles, with `ci/publish-plugins.sh` right after bnd's release:

| Branch | Version | Targets |
|---|---|---|
| `snapshot` | `<base-version>-SNAPSHOT` | DIM Nexus `dim-snapshot`, Central Portal snapshot repository |
| `main` | `<base-version>`, signed, with sources and javadoc | DIM Nexus `dim-release`, and `dist/bundles` — the same Central Portal deployment as the bundles |

The version is the workspace's `base-version` (`cnf/ext/fennec.bnd`), so the plugins, the
library and the CLI of one build carry the same version, and the Gradle plugin runs the CLI of
its own version by default. The Maven plugin is built against the `org.gecko.bnd.update` jar of
the same build; the script refuses to run when that jar has another version. The script fetches
Maven itself (pinned version, checked against its SHA-512, unpacked with `tar`, cached in
`~/.cache/bnd-update`), the Gradle plugin is built with the workspace's Gradle wrapper: the
agent needs only Java 21, curl and tar.

The targets can be redirected for a trial (`NEXUS_SNAPSHOT_URL`, `NEXUS_RELEASE_URL`,
`CENTRAL_SNAPSHOT_URL`, `DIST_DIR`), e.g. to local directories:

```
./gradlew assemble
NEXUS_SNAPSHOT_URL=file:///tmp/repo ci/publish-plugins.sh
```
