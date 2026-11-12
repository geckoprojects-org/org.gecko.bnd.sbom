# Example: a bnd workspace with Gradle

A small bnd workspace, built with Gradle, that uses both tools of this repository:

- the **SBOM exporter** writes the SBOM of the application `example.app/app.bndrun`;
- the **bnd update Gradle plugin** (`org.geckoprojects.bnd.update`) finds updates and fixes for
  vulnerabilities in that SBOM, checks that every bndrun still resolves, and applies the updates.

```
gradle-workspace/
  settings.gradle         bnd workspace plugin 7.4.0
  build.gradle            bnd update plugin, configuration bndUpdate { }, fetching the SBOM exporter
  cnf/build.bnd           Maven repository Central (index cnf/central.mvn), -update-policy
  cnf/central.mvn         the libraries: one groupId:artifactId:version per line
  example.app/            a bundle (slf4j) and app.bndrun: the application on Apache Felix
  trivy-sample.json       a Trivy report with two made-up findings, for trying it without Trivy
  Jenkinsfile             the pipeline: build, SBOM, Trivy, fixes, weekly update pull request
```

The commands below use the Gradle wrapper of this repository (`../../gradlew`). In a copy of
the example, run `gradle wrapper` once and use `./gradlew`.

## The SBOM

```
../../gradlew sbom
```

writes `example.app/generated/sbom/app.bndrun.cdx.json` (CycloneDX 1.6, `-sbom: level=medium`
in `app.bndrun`: with hashes and licenses).

How the exporter gets there: it is a bnd plugin, not a Gradle plugin. The root project fetches
`org.geckoprojects.bnd:org.gecko.bnd.sbom` through the Gradle configuration `sbomExporter` (so
Gradle verifies it and Dependabot sees its version) and copies it to
`cnf/cache/sbom-exporter/`. `app.bndrun` registers it from there:

```
-plugin.sbom: \
	org.gecko.bnd.sbom.SbomExporter;\
		path:="${workspace}/cnf/cache/sbom-exporter/org.gecko.bnd.sbom.jar"
```

Every task that reads the bndrun (export, resolve, testOSGi, `bndResolveCheck`, `bndApply`)
depends on the copy task. Registering the plugin in the bndrun rather than in `cnf/build.bnd`
means bnd loads it only when a bndrun is processed, after the copy.

Alternative without Gradle, for a released version: bnd downloads the plugin itself, checked
against its SHA-1:

```
# cnf/build.bnd
-pluginpath.sbom: ${workspace}/cnf/cache/org.gecko.bnd.sbom-<version>.jar;\
	url=https://repo.maven.apache.org/maven2/org/geckoprojects/bnd/org.gecko.bnd.sbom/<version>/org.gecko.bnd.sbom-<version>.jar;\
	sha1=<sha1>
-plugin.sbom: org.gecko.bnd.sbom.SbomExporter
```

## Vulnerabilities and their fixes

```
trivy sbom --format json --output trivy.json example.app/generated/sbom/app.bndrun.cdx.json
../../gradlew bndVulnerabilities
```

matches the Trivy report against the versions in the repository, within the version policy:
`build/bnd-update/vulnerabilities.md`. Without Trivy, with the sample report:

```
../../gradlew sbom bndVulnerabilities -PtrivyReport=trivy-sample.json
```

| Library | Installed | Vulnerabilities | Fix | Where |
|---|---|---|---|---|
| `org.slf4j:slf4j-api` | 2.0.17 | 1 (HIGH) | **2.0.18** (minor) | runbundle, Central |
| `org.apache.felix:org.apache.felix.framework` | 7.0.5 | 1 (MEDIUM) | needs a major update (allowed: micro) | runfw, Central |

The scope in parentheses is what the policy allows for that library. `cnf/build.bnd` allows
minor updates for slf4j (`-update-policy: default;scope=micro, org.slf4j:*;scope=minor`); the
framework would need a major update, which is never applied automatically.

`-PfailOnFindings=true` fails the task in that case — the Jenkinsfile uses it to mark the build
unstable.

## Updates, resolve check, apply

```
../../gradlew bndUpdates        # newer versions within the policy: build/bnd-update/updates.md
../../gradlew bndResolveCheck   # does every bndrun still resolve?  build/bnd-update/resolve.md
../../gradlew bndApply          # CHANGES cnf/central.mvn and -runbundles
```

`bndApply` applies the proposed updates one by one (`mode = 'each'`): after each one it resolves
every bndrun and runs `buildCommand` (`./gradlew build`), and reverts the update if either fails.
What remains is committed by you — or, in CI, by `ci/bnd-update.sh`, which opens a pull request
(the weekly stage of the Jenkinsfile).

## Configuration

`build.gradle`:

```groovy
bndUpdate {
    scope = 'micro'                      // default scope; -update-policy in cnf/build.bnd refines it
    trivyReport = file('trivy.json')     // bndVulnerabilities
    sbom = file('example.app/generated/sbom/app.bndrun.cdx.json')
    buildCommand = './gradlew build --no-daemon'   // bndApply
    failOnFindings = false
}
```

All options: [docs/bnd-update.md](../../docs/bnd-update.md#gradle).

## Jenkins

`Jenkinsfile` runs on every build:

| Stage | Does | Result |
|---|---|---|
| Build | `./gradlew build` | |
| SBOM | `./gradlew sbom` | archived |
| Trivy | `trivy sbom` on the SBOM (Trivy on the agent, or the Docker variant in a comment) | `trivy.json`, archived |
| Fixes | `bndVulnerabilities bndResolveCheck -PfailOnFindings=true` | reports archived; build **unstable** when a vulnerability has no fix within the policy or a bndrun does not resolve |

and once a week on `main` (cron, or started by hand) the stage **bnd update**: it applies the
verified updates and opens or updates one pull request through `ci/bnd-update.sh`, pinned to a
commit and its SHA-256. Setup (token, credential, identity): [ci/jenkins/README.md](../../ci/jenkins/README.md).
