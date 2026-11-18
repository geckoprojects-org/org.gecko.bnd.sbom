# bnd update with Gradle

For bnd workspaces built with Gradle, the plugin `org.geckoprojects.bnd.update` adds the four
functions of [bnd update](bnd-update.md) as tasks of the root project. A runnable workspace with
the plugin, the SBOM exporter and a Jenkinsfile is
[examples/gradle-workspace](../examples/gradle-workspace/README.md).

| Task | Function | Changes files | Report |
|---|---|---|---|
| `bndUpdates` | [updates](bnd-update.md#function-1-updates): newer versions within the policy | no | `build/bnd-update/updates.md` |
| `bndVulnerabilities` | [vulnerabilities](bnd-update.md#function-2-vulnerabilities): fix versions for a Trivy report; needs `trivyReport` | no | `build/bnd-update/vulnerabilities.md` |
| `bndResolveCheck` | [resolve](bnd-update.md#function-3-resolve): does every bndrun resolve? Depends on every project's `jar` | no | `build/bnd-update/resolve.md` |
| `bndApply` | [apply](bnd-update.md#function-4-apply): applies and verifies updates. Depends on every project's `jar` | **yes** | `build/bnd-update/apply.md` |

The file extension follows `format`: `.md`, `.json` or `.txt`.

## Installation

The plugin is published to Maven Central (not to the Gradle Plugin Portal), as the plugin marker
`org.geckoprojects.bnd.update:org.geckoprojects.bnd.update.gradle.plugin` and the artifact
`org.geckoprojects.bnd:bnd-update-gradle-plugin`. Snapshots are in the Central Portal's snapshot
repository.

`settings.gradle`:

```groovy
pluginManagement {
    repositories {
        mavenCentral()
        // only for -SNAPSHOT versions
        maven { url = 'https://central.sonatype.com/repository/maven-snapshots/' }
        gradlePluginPortal()
    }
}

plugins {
    id 'biz.aQute.bnd.workspace' version '7.4.0'
}
```

`build.gradle` of the root project:

```groovy
plugins {
    id 'org.geckoprojects.bnd.update' version '<version>'
}

// where the bnd update CLI comes from
repositories {
    mavenCentral()
    // only for -SNAPSHOT versions
    maven { url = 'https://central.sonatype.com/repository/maven-snapshots/' }
}
```

The tasks run the [CLI](bnd-update.md#command-line) jar
(`org.geckoprojects.bnd:org.gecko.bnd.update.cli`, configuration `bndUpdateCli`) in **its own
JVM**. The bnd Gradle plugin already brings a bndlib into the build, and a second one of another
version in the same class loader would conflict. By default the CLI of the plugin's own version is
used.

## Configuration

```groovy
bndUpdate {
    scope = 'micro'                          // unset: the workspace's -update-policy
    mode = 'each'                            // bndApply: each or all
    only = ['com.fasterxml.jackson.*:*']     // bndApply: only these libraries
    buildCommand = './gradlew build -x test --no-daemon'  // bndApply: verifies each update
    trivyReport = file('trivy.json')         // bndVulnerabilities; bndApply then applies its fixes
    sbom = file('app/generated/sbom/app.bndrun.cdx.json')
    format = 'markdown'                      // text, json, markdown
    failOnFindings = false                   // fail the task on exit code 2
    // cliJar.from('path/to/org.gecko.bnd.update.cli.jar'), or cliVersion = '...'
}
```

| Property | Meaning | Default |
|---|---|---|
| `scope` | default scope of the policy for the run: `micro`, `minor`, `major`. The per-library entries of `-update-policy` stay | unset: `-update-policy`, else `micro` |
| `mode` | `bndApply`: `each` (one by one, keep what passes) or `all` (together, all or nothing) | `each` |
| `only` | `bndApply`: only these libraries, `groupId:artifactId` patterns, `*` matches any part | all proposed |
| `buildCommand` | `bndApply`: command run in the workspace after resolving; a failing build reverts the update | none: resolving is the only check |
| `trivyReport` | Trivy JSON report. Required for `bndVulnerabilities`; with it, `bndApply` applies the fixes for the report instead of all updates | none |
| `sbom` | the CycloneDX SBOM the Trivy report was made from; adds where each library sits | none |
| `format` | `markdown`, `json` or `text` | `markdown` |
| `outputDirectory` | where the reports go | `build/bnd-update` |
| `failOnFindings` | fail the task on exit code 2: a vulnerability without a fix within the policy, a bndrun that does not resolve, a reverted update | `false` |
| `cliJar` | a local CLI jar instead of the published one | none |
| `cliVersion` | version of the CLI to fetch | the plugin's version |

The version policy itself is not configured here but in the workspace, with `-update-policy` in
`cnf/build.bnd`, so that the CLI, the CI adapters and the plugin all follow the same rules. See
[the version policy](bnd-update.md#the-version-policy).

### Configuration from the command line

The extension does not read Gradle properties by itself. To set values per call (e.g. in CI),
read them in `build.gradle`:

```groovy
bndUpdate {
    trivyReport = file(providers.gradleProperty('trivyReport').getOrElse('trivy.json'))
    failOnFindings = providers.gradleProperty('failOnFindings').map { it == 'true' }.orElse(false)
}
```

```
./gradlew bndVulnerabilities -PtrivyReport=build/trivy.json -PfailOnFindings=true
```

## Exit codes and results

| CLI exit code | Meaning | Task |
|---|---|---|
| 0 | nothing to do | succeeds |
| 1 | updates or fixes found, or updates applied | succeeds |
| 2 | something needs a decision | fails only with `failOnFindings = true` |
| anything else | usage or internal error | always fails |

The tasks are **never up to date**: the answer depends on the repositories, not only on the
inputs.

## Typical uses

### See what could be updated

```
./gradlew bndUpdates
cat build/bnd-update/updates.md
```

### Fixes for the vulnerabilities of an application

```
./gradlew :app:sbom
trivy sbom --format json --output trivy.json app/generated/sbom/app.bndrun.cdx.json
./gradlew bndVulnerabilities
```

```
## Vulnerabilities — app.bndrun

| Library | Installed | Vulnerabilities | Fix | Where |
|---|---|---|---|---|
| `org.slf4j:slf4j-api` | 2.0.17 | 1 (HIGH) | **2.0.18** (minor) | runbundle, Central |
| `org.apache.felix:org.apache.felix.framework` | 7.0.5 | 1 (MEDIUM) | needs a major update (allowed: micro) | runfw, Central |
```

The scope in parentheses is what the policy allows for that library. Here slf4j may take minor
steps (`-update-policy: default;scope=micro, org.slf4j:*;scope=minor`); the framework would need a
major update, which is never applied automatically.

When the SBOM is exported in the same Gradle call, order the tasks:

```groovy
['bndVulnerabilities', 'bndApply'].each { name ->
    tasks.named(name) { mustRunAfter ':app:sbom' }
}
```

### Check that every bndrun still resolves

```
./gradlew bndResolveCheck
```

```
## Resolving all bndruns

Every bndrun resolves.

| bndrun | Result |
|---|---|
| `example.app/app.bndrun` | resolves, unchanged |
```

Run it after any manual change to a `.mvn` index or a `-buildpath` version. Then
`./gradlew resolve` writes the new `-runbundles`.

### Apply updates locally

```
git switch -c updates
./gradlew bndApply
git diff
./gradlew build testOSGi
git commit -s -am "Dependency updates"
```

`bndApply` applies every proposed update (or only `only`, or the fixes of `trivyReport`), checks
each with a resolve of every bndrun and `buildCommand`, and reverts what fails. Run it on a clean
working copy: it rewrites files.

### Only some libraries, a larger step

```groovy
bndUpdate {
    only = ['com.fasterxml.jackson.core:*']
    scope = 'minor'
}
```

or permanently, per library, in `cnf/build.bnd`:

```
-update-policy: default;scope=micro, com.fasterxml.jackson.core:*;scope=minor
```

## When the bndruns load the SBOM exporter

If the bndruns register the SBOM exporter with `-plugin.sbom` and a `path:=` that a Gradle task
fills (see [SBOMs with Gradle](sbom-gradle.md)), `bndResolveCheck` and `bndApply` read those
bndruns and need the jar too:

```groovy
['bndResolveCheck', 'bndApply'].each { name ->
    tasks.named(name) { dependsOn 'sbomExporter' }
}
```

## In CI

- Reports on every build: [SBOMs in CI](sbom-ci.md).
- A weekly pull/merge request with the verified updates: [bnd update in CI](bnd-update-ci.md).
  In CI, use the GitHub Action or `ci/bnd-update.sh` rather than `bndApply`: they also commit,
  push and open the request.
