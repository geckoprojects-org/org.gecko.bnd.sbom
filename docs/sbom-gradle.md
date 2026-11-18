# SBOMs in a bnd workspace built with Gradle

This page shows step by step how a bnd workspace built with Gradle (`biz.aQute.bnd.workspace`)
writes the SBOMs of its bndruns. The options of the exporter itself are in the
[reference](sbom-exporter.md).

A complete, runnable workspace with everything on this page is
[examples/gradle-workspace](../examples/gradle-workspace/README.md).

## What you get

```
./gradlew sbom
```

writes `example.app/generated/sbom/app.bndrun.cdx.json`, the SBOM of `example.app/app.bndrun`.

## Prerequisites

- a bnd workspace with Gradle (`settings.gradle` applies `biz.aQute.bnd.workspace`, bnd 7.4 or
  later),
- Java 21,
- a resolved `.bndrun` with `-runbundles`.

## 1. Fetch the exporter

The exporter is a bnd plugin, not a Gradle plugin. Let Gradle download it: Gradle verifies the
download, the version is in `build.gradle` where Dependabot and Renovate see it, and nothing
binary is checked in.

In the `build.gradle` of the **root project**:

```groovy
repositories {
    mavenCentral()
    // only for -SNAPSHOT versions
    maven { url = 'https://central.sonatype.com/repository/maven-snapshots/' }
}

configurations {
    sbomExporter {
        canBeConsumed = false
        transitive = false
    }
}

dependencies {
    sbomExporter 'org.geckoprojects.bnd:org.gecko.bnd.sbom:<version>'
}

// copies the exporter to where the bndruns load it from
tasks.register('sbomExporter', Sync) {
    description = 'Copies the SBOM exporter to cnf/cache/sbom-exporter/.'
    from configurations.sbomExporter
    into 'cnf/cache/sbom-exporter'
    rename { 'org.gecko.bnd.sbom.jar' }
}
```

Make sure `cnf/cache/` is in `.gitignore` (bnd keeps its caches there as well), so the copy is
not committed.

## 2. Register the exporter in the bndrun

In each `.bndrun` that should get an SBOM:

```
-plugin.sbom: \
	org.gecko.bnd.sbom.SbomExporter;\
		path:="${workspace}/cnf/cache/sbom-exporter/org.gecko.bnd.sbom.jar"
```

Why in the bndrun and not in `cnf/build.bnd`: Gradle reads the workspace before any task runs,
so a plugin in `cnf/build.bnd` would be looked for before `sbomExporter` has copied it. In the
bndrun it is only loaded when the bndrun is processed.

## 3. Configure the SBOM

In the same `.bndrun`:

```
-sbom: level=medium, format=cyclonedx, validate=bsi-tr-03183-2
```

All options: [reference](sbom-exporter.md#options-reference). Vendor, contact and licence
belong in `cnf/build.bnd`, so that the SBOM, the application and every workspace bundle have a
creator:

```
Bundle-Vendor: Example Org
Bundle-ContactAddress: security@example.org
Bundle-DocURL: https://example.org
Bundle-License: Apache-2.0;link="https://www.apache.org/licenses/LICENSE-2.0"
```

## 4. Add an export task

In the `build.gradle` of the **project that contains the bndrun**:

```groovy
import aQute.bnd.gradle.Export
import aQute.bnd.gradle.Resolve
import aQute.bnd.gradle.TestOSGi

// every task that reads a bndrun with -plugin.sbom needs the exporter jar first
[Export, Resolve, TestOSGi].each { type ->
    tasks.withType(type).configureEach {
        dependsOn rootProject.tasks.named('sbomExporter')
    }
}

// ./gradlew sbom: the SBOM of app.bndrun
tasks.register('sbom', Export) {
    description = 'Writes the SBOM of app.bndrun.'
    group = 'export'
    bndrun = file('app.bndrun')
    exporter = 'bnd.sbom'
    destinationDirectory = layout.projectDirectory.dir('generated/sbom')
}
```

The `dependsOn` matters: `resolve`, `testOSGi` and the bnd update tasks read the bndrun as well,
and bnd fails on a `-plugin` whose jar does not exist yet.

### Several bndruns

One task per bndrun:

```groovy
['app', 'app-cloud', 'app-edge'].each { name ->
    tasks.register("sbom-${name}", Export) {
        group = 'export'
        bndrun = file("${name}.bndrun")
        exporter = 'bnd.sbom'
        destinationDirectory = layout.buildDirectory.dir("sbom/${name}")
    }
}
tasks.register('sbom') {
    group = 'export'
    dependsOn tasks.matching { it.name.startsWith('sbom-') }
}
```

### Several formats of one application

Give each format its own small bndrun that includes the application:

```
# app-spdx.bndrun
-include: ~${.}/app.bndrun
-sbom: level=medium, format=spdx, spdx.version=3.0.1
```

and an export task for it as above. The `~` lets the including file's `-sbom` win over the one of
`app.bndrun`. This repository does exactly that for its own runtime
(`org.gecko.bnd.sbom/build.gradle`).

## 5. Run it

```
./gradlew sbom
./gradlew :example.app:sbom          # only this project
```

Resolve before exporting when the `-runbundles` may be out of date: the export describes what
is in the file.

```
./gradlew :example.app:resolve.app :example.app:sbom
```

## Making the SBOM part of every build

```groovy
tasks.named('build') { dependsOn 'sbom' }
```

To publish the SBOM next to the application, add it to the artifacts of whatever ships the
application (a container image, a distribution archive), or attach it to a release.

## Using a locally built exporter

To try an exporter that is not published yet, let the `Sync` task take a jar from a property:

```groovy
def exporterJar = providers.gradleProperty('sbomExporterJar')
tasks.register('sbomExporter', Sync) {
    from(exporterJar.isPresent() ? files(exporterJar.get()) : configurations.sbomExporter)
    into 'cnf/cache/sbom-exporter'
    rename { 'org.gecko.bnd.sbom.jar' }
}
```

```
./gradlew sbom -PsbomExporterJar=/path/to/org.gecko.bnd.sbom.jar
```

## Next steps

- Scan the SBOM and publish it in CI: [SBOMs in CI](sbom-ci.md).
- Find updates and fixes for what the scan reports: [bnd update with Gradle](bnd-update-gradle.md).
