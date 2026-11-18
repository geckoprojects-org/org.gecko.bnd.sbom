# The SBOM exporter

`org.gecko.bnd.sbom` is a bnd exporter plugin. It writes a Software Bill of Materials (SBOM) for
the **resolved OSGi application** of a `.bndrun`: the bundles it runs (`-runbundles`), the
framework underneath (`-runfw`, `-runpath`), the libraries those bundles carry inside, and the
dependencies between all of them.

This page is the reference: what the exporter does, how it is configured, every option, and
what ends up in the SBOM. How to run it in a build is on separate pages:

- [Gradle (bnd workspace)](sbom-gradle.md)
- [Maven (bnd Maven plugins)](sbom-maven.md)
- [In CI: SBOM, Trivy, GitLab, GitHub, Jenkins](sbom-ci.md)

**Contents**

- [Why an SBOM of the bndrun](#why-an-sbom-of-the-bndrun)
- [Quick start](#quick-start)
- [Installing the exporter](#installing-the-exporter)
- [Running an export](#running-an-export)
- [Configuration](#configuration)
- [Options reference](#options-reference)
- [Levels](#levels)
- [Output formats](#output-formats)
- [What the SBOM contains](#what-the-sbom-contains)
- [BSI TR-03183-2](#bsi-tr-03183-2)
- [Reproducible SBOMs](#reproducible-sboms)
- [Bundles from p2 or OBR repositories](#bundles-from-p2-or-obr-repositories)
- [Security](#security)
- [Troubleshooting](#troubleshooting)

| | |
|---|---|
| Maven coordinates | `org.geckoprojects.bnd:org.gecko.bnd.sbom` |
| Plugin class | `org.gecko.bnd.sbom.SbomExporter` |
| Export type | `bnd.sbom` |
| Output | `<name>.bndrun.cdx.json` (CycloneDX) or `<name>.bndrun.spdx.json` (SPDX) |
| Requires | bnd 7.4 or later, Java 21 |

## Why an SBOM of the bndrun

In OSGi a bundle rarely has fixed dependencies: it imports **packages with version ranges**,
and which bundle provides them is decided when the application is resolved. An SBOM of a single
bundle (Maven or Gradle plugins, a generated `MANIFEST.MF`) therefore lists either too much (the
whole build path) or too little (nothing that is only imported).

What runs is defined by the resolved `.bndrun`: its `-runbundles` with exact versions, plus the
framework and its class path. That is what the exporter describes. Its SBOM answers "which
components are in the application we ship, in which version, from where, under which licence,
and who depends on whom", which is what vulnerability scanners and regulations
(EU CRA, BSI TR-03183-2, NTIA minimum elements) need.

## Quick start

1. Register the exporter in the `.bndrun` (or for every bndrun in `cnf/build.bnd`):

   ```
   -plugin.sbom: org.gecko.bnd.sbom.SbomExporter;path:="${workspace}/cnf/cache/sbom-exporter/org.gecko.bnd.sbom.jar"
   ```

2. Configure it in the same `.bndrun`:

   ```
   -sbom: level=medium, format=cyclonedx
   ```

3. Export:

   ```
   bnd export --exporter bnd.sbom app.bndrun
   ```

   or with Gradle or Maven, see [Gradle](sbom-gradle.md) and [Maven](sbom-maven.md).

The result, `app.bndrun.cdx.json`, can go straight to Trivy, Grype, Dependency-Track or GitLab.

## Installing the exporter

The exporter is a jar that bnd loads as a plugin. bnd has to find it before it processes the
bndrun. There are three ways to provide it.

### 1. Let the build tool fetch it (recommended)

The build tool downloads `org.geckoprojects.bnd:org.gecko.bnd.sbom` like any other dependency,
verified by its checksum and visible to Dependabot or Renovate, and puts it where the bndrun
expects it:

- **Gradle**: a configuration and a `Sync` task copy it to `cnf/cache/sbom-exporter/`. See
  [Gradle](sbom-gradle.md#1-fetch-the-exporter).
- **Maven**: it is a plugin dependency of `bnd-export-maven-plugin`. Nothing has to be copied.
  See [Maven](sbom-maven.md).

### 2. Let bnd download it

For a released version bnd can download the plugin itself and check it against its SHA-1. In
`cnf/build.bnd`:

```
-pluginpath.sbom: ${workspace}/cnf/cache/org.gecko.bnd.sbom-<version>.jar;\
	url=https://repo.maven.apache.org/maven2/org/geckoprojects/bnd/org.gecko.bnd.sbom/<version>/org.gecko.bnd.sbom-<version>.jar;\
	sha1=<sha1 of the jar>
-plugin.sbom: org.gecko.bnd.sbom.SbomExporter
```

The SHA-1 is published next to the jar (`.jar.sha1`). Snapshot versions change their file name
with every build, so this is for releases only.

### 3. A jar in the workspace

Check the jar into the repository (e.g. `cnf/plugins/org.gecko.bnd.sbom.jar`) and point to it:

```
-plugin.sbom: org.gecko.bnd.sbom.SbomExporter;path:="${workspace}/cnf/plugins/org.gecko.bnd.sbom.jar"
```

Simple, but nobody is told about new versions.

### In the bndrun or in the workspace?

`-plugin.sbom` can be set in `cnf/build.bnd` (every bndrun can export SBOMs) or in a single
`.bndrun`. Registering it in the `.bndrun` means bnd loads the plugin only when that bndrun is
processed. That matters with option 1: Gradle copies the jar during the build, after the
workspace has been read. A plugin in `cnf/build.bnd` would be looked for before it is there.

## Running an export

The exporter runs when an export of type `bnd.sbom` is requested. `-sbom` only configures it, it
does not trigger it.

| Build | Command |
|---|---|
| bnd CLI | `bnd export --exporter bnd.sbom app.bndrun` |
| bnd CLI with options | `bnd export --exporter "bnd.sbom;level=medium;format=spdx" app.bndrun` |
| Gradle | an `aQute.bnd.gradle.Export` task with `exporter = 'bnd.sbom'`, see [Gradle](sbom-gradle.md) |
| Maven | `bnd-export-maven-plugin` with `<exporter>bnd.sbom</exporter>`, see [Maven](sbom-maven.md) |

The bndrun is **not resolved** by the export: the exporter describes the `-runbundles` that are
in the file. Resolve first (`./gradlew resolve`, `bnd resolve`, or `<resolve>true</resolve>` in
Maven) when the file may be out of date.

### Making it the default export of a bndrun

With `-exporttype` a plain `bnd export app.bndrun` writes the SBOM:

```
-exporttype: bnd.sbom;level=medium;format=spdx
```

Here the options are attributes of the export type and are separated by **semicolons**.

## Configuration

Options can be given in three places. Later ones win:

1. the `-sbom` instruction in the `.bndrun` (or inherited from `cnf/build.bnd`),
2. the attributes of `-exporttype: bnd.sbom;...`,
3. the options of the export call (`--exporter "bnd.sbom;level=medium"`, or the Maven and
   Gradle export configuration).

`-sbom` is a comma separated list; semicolons work as well:

```
-sbom: level=medium, format=cyclonedx, validate=bsi-tr-03183-2
```

Across several lines:

```
-sbom: \
	level=medium,\
	format=spdx,\
	spdx.version=3.0.1,\
	creator=security@example.org,\
	property.vcs:commit=${env;GITHUB_SHA;local}
```

bnd macros work in the values (`${env;...}`, `${version;...}`).

**Invalid values** (`level=mediun`, `format=xml`) are reported as errors and **no SBOM is
written**. **Unknown options** (`levle=medium`) are reported as warnings and ignored. The
messages list the valid values.

A value that contains a comma or a semicolon, e.g. a PURL with qualifiers, must be quoted:

```
-sbom: application.purl="pkg:oci/weather@sha256%3Aabc?repository_url=ghcr.io/example"
```

## Options reference

### Content and format

| Option | Values | Default | Meaning |
|---|---|---|---|
| `level` | `simple`, `medium`, `full` | `simple` | How much is written, see [Levels](#levels) |
| `format` | `cyclonedx`, `spdx` | `cyclonedx` | Output format, see [Output formats](#output-formats) |
| `cyclonedx.version` | `1.6`, `1.7` | `1.6` | CycloneDX specification version; the `$schema` matches it |
| `spdx.version` | `2.3`, `3.0.1` | `2.3` | SPDX version: 2.3 as JSON, 3.0.1 as JSON-LD |
| `includeOSGIMetadata` | `true`, `false` | `false` | Reserved for the import ranges and capabilities of each bundle; has no effect yet |

### Identity of the application

The application is the bndrun itself: `metadata.component` in CycloneDX, the root package in
SPDX.

| Option | Default | Meaning |
|---|---|---|
| `application.name` | the bndrun's file name, e.g. `app.bndrun` | Name of the application |
| `application.group` | `-groupid` of the workspace | Group (organisation) of the application |
| `application.version` | `Bundle-Version` of the bndrun or workspace; with a Maven-style `-groupid`, `0.1.1.SNAPSHOT` becomes `0.1.1-SNAPSHOT` | Version of the application |
| `application.purl` | none | PURL of what is shipped, e.g. the container image built from the bndrun; also its `bom-ref`. Not derived from the workspace's coordinates, because the application is not published under them |

Example for an application shipped as a container image:

```
-sbom: \
	level=medium,\
	application.name=weather-service,\
	application.version=${version;===;${Bundle-Version}},\
	application.purl="pkg:oci/weather-service@${env;IMAGE_DIGEST}?repository_url=ghcr.io/example"
```

### Creator (BSI TR-03183-2)

| Option | Default | Meaning |
|---|---|---|
| `creator` | at `medium`: derived from the project the bndrun lives in, see below | Creator of the SBOM and of the application, as an email address or an http(s) URL |

At `medium` the exporter takes the creator from the **bnd project the `.bndrun` lives in**,
including what that project inherits from `cnf/build.bnd`:

- name: `Bundle-Vendor`,
- contact: an email address in `Bundle-ContactAddress`, else a URL there, else
  `Bundle-DocURL`.

A `.bndrun` does not inherit the `bnd.bnd` of its project, so the exporter looks that project
up itself. When the project has nothing, the `.bndrun` and the workspace are used. `creator=`
replaces the email or URL and keeps the name. bnd is listed as the tool that wrote the SBOM,
never as its creator.

The simplest setup is in `cnf/build.bnd`, so every bundle carries it in its manifest as well:

```
Bundle-Vendor: Example Org
Bundle-ContactAddress: security@example.org
Bundle-DocURL: https://example.org
Bundle-License: Apache-2.0;link="https://www.apache.org/licenses/LICENSE-2.0"
```

### Scope of delivery

| Option | Values | Default | Meaning |
|---|---|---|---|
| `framework` | `delivered`, `provided` | `delivered` | Whether the OSGi framework (`-runfw`) and its class path (`-runpath`) are part of what you ship |

An application usually ships with its framework, so `delivered` is the default. A library, or
a test setup, runs on whichever framework the user installs. With `framework=provided` the
`-runfw` and `-runpath` components are only identified: the version they were resolved against
is written as **minimum version** (`osgi:version:kind=minimum`), they are marked
`osgi:delivery=provided`, and they have no file name, hash or file properties. The `.bndrun`
cannot tell which of the two it is, so you have to say it.

### Checks

| Option | Values | Default | Meaning |
|---|---|---|---|
| `validate` | `bsi-tr-03183-2` | none | Checks the SBOM against the required fields of BSI TR-03183-2 v2.1.0 and reports every gap. The SBOM is written either way |
| `validate.strict` | `true`, `false` | `false` | `true`: the gaps are build errors instead of warnings |

### Reproducibility and metadata

| Option | Values | Default | Meaning |
|---|---|---|---|
| `timestamp` | ISO-8601 instant, e.g. `2026-01-01T00:00:00Z` | time of the export | Creation time written into the SBOM |
| `serialNumber` | `content`, `random` | `content` | `content`: derived from format, level, application and components, so an unchanged application keeps its serial number; `random`: a new one per export |
| `property.<name>` | any text | none | Free properties of the SBOM: CycloneDX `metadata.properties`, in SPDX the document comment |

```
-sbom: \
	level=medium,\
	property.vcs:commit=${env;GITHUB_SHA;local},\
	property.ci:build=${env;BUILD_NUMBER;local}
```

### Maven identity of bundles from other repositories

| Option | Values | Meaning |
|---|---|---|
| `maven.<bsn>` | `groupId:artifactId[:version]` | Maven coordinates of a bundle that comes from a p2 or OBR repository but is also published to Maven Central. The version defaults to the bundle's `major.minor.micro` |

See [Bundles from p2 or OBR repositories](#bundles-from-p2-or-obr-repositories).

## Levels

The levels build on each other: `medium` contains everything of `simple`.

| | `simple` | `medium` |
|---|---|---|
| Every run bundle, the framework, the `-runpath` | ✓ | ✓ |
| Name, version, PURL (Maven coordinates where verified) | ✓ | ✓ |
| OSGi identity (`osgi:bundle:symbolicName`, `osgi:bundle:version`) | ✓ | ✓ |
| Layer (`osgi:layer`), origin repository, download URL | ✓ | ✓ |
| Embedded libraries as components of their own | ✓ | ✓ |
| Dependency graph and completeness | ✓ | ✓ |
| SHA-512 hash and file name | | ✓ |
| Licences (SPDX ids or expressions where they can be told with confidence) | | ✓ |
| Creator of the SBOM, the application and each component | | ✓ |
| File properties: executable, archive, structured | | ✓ |
| Java SE as a component (minimum version from `-runee`) | | ✓ |

`simple` covers the NTIA minimum elements and is enough to match components against
vulnerability databases. `medium` is what the EU Cyber Resilience Act and BSI TR-03183-2 ask
for, and the level to use for anything you hand to customers or authorities.

`full` is reserved for further evidence (supplier, linking). Today it writes the same as
`medium`.

## Output formats

| | CycloneDX | SPDX 2.3 | SPDX 3.0.1 |
|---|---|---|---|
| Option | `format=cyclonedx` | `format=spdx` | `format=spdx, spdx.version=3.0.1` |
| File | `<name>.bndrun.cdx.json` | `<name>.bndrun.spdx.json` | `<name>.bndrun.spdx.json` (JSON-LD) |
| Read by | Trivy, Grype, Dependency-Track, GitLab, most SCA tools | Trivy, Grype, GitHub, most SCA tools | few tools yet |
| BSI TR-03183-2 | yes (1.6 and 1.7) | no, the TR requires SPDX 3.0.1 | yes |
| OSGi facts | as `properties` | in comments | in comments |

**CycloneDX is the recommended format.** It carries the OSGi facts as named properties, and
every common tool reads it. Use SPDX when a customer or a tool requires it.

All three are written with plain JSON, without external libraries. The CI of this repository
validates every format against its official schema.

## What the SBOM contains

The excerpts below are from the SBOM of `examples/gradle-workspace` (`-sbom: level=medium`).

### The application

```json
"metadata": {
  "timestamp": "2026-11-18T14:47:56Z",
  "manufacturer": { "name": "Example Org", "contact": [ { "email": "sbom@example.org" } ] },
  "component": {
    "bom-ref": "app.bndrun",
    "type": "application",
    "group": "org.example",
    "name": "app.bndrun",
    "manufacturer": { "name": "Example Org", "contact": [ { "email": "sbom@example.org" } ] },
    "externalReferences": [ { "type": "website", "url": "https://example.org" } ]
  },
  "tools": { "components": [ { "name": "org.gecko.bnd.sbom", ... }, { "name": "bnd", "version": "7.4.0", ... } ] }
}
```

### A bundle from Maven Central

```json
{
  "bom-ref": "pkg:maven/org.slf4j/slf4j-api@2.0.17",
  "type": "library",
  "group": "org.slf4j",
  "name": "slf4j-api",
  "version": "2.0.17",
  "purl": "pkg:maven/org.slf4j/slf4j-api@2.0.17",
  "manufacturer": { "name": "SLF4J.ORG", "url": [ "http://www.slf4j.org" ] },
  "hashes": [ { "alg": "SHA-512", "content": "9A3E79DB..." } ],
  "licenses": [ { "license": { "id": "MIT", "url": "https://opensource.org/license/mit", "acknowledgement": "concluded" } } ],
  "properties": [
    { "name": "osgi:bundle:symbolicName", "value": "slf4j.api" },
    { "name": "osgi:bundle:version", "value": "2.0.17" },
    { "name": "bsi:component:filename", "value": "slf4j-api-2.0.17.jar" },
    { "name": "bsi:component:executable", "value": "executable" },
    { "name": "bsi:component:archive", "value": "archive" },
    { "name": "bsi:component:structured", "value": "structured" },
    { "name": "osgi:layer", "value": "runbundle" },
    { "name": "osgi:repository:name", "value": "Central" },
    { "name": "osgi:repository:kind", "value": "maven" }
  ],
  "externalReferences": [
    { "type": "distribution", "url": "slf4j-api-2.0.17.jar", "hashes": [ { "alg": "SHA-512", "content": "9A3E79DB..." } ] }
  ]
}
```

Name and version follow the **Maven identity** (`slf4j-api`), because that is what
vulnerability databases know. The OSGi identity (`slf4j.api`) stays in the properties.

### Components

| What | Where from | Notes |
|---|---|---|
| Run bundles | `-runbundles` | `osgi:layer=runbundle`: installed in the framework, can be updated there |
| Framework | `-runfw` | `osgi:layer=runfw`: on the framework's class path, replaced only by rebuilding the launch |
| Framework class path | `-runpath` | `osgi:layer=runpath`, as above |
| Embedded libraries | inside a bundle | components of their own, `osgi:embedded:in` names the bundle |
| Java SE | `-runee` or the bundles' requirements | `medium` only, see [Java SE](#java-se-is-a-standard) |

`-runsystempackages` and `-runsystemcapabilities` add no components: they only declare what
the framework, the `-runpath` or the JDK export.

### Identity: PURL or not

A component gets a PURL only when its Maven coordinates are **verified**: from the Maven
repository it was taken from, or from the `pom.properties` inside the jar that match the bundle.
Bundles built in the workspace, or taken from p2 and OBR repositories, have no reliable Maven
identity. They keep their OSGi name and version, have no PURL, and are marked
`osgi:identity:matchability=unverified`. A guessed PURL would silently break the link to
vulnerability databases, so none is invented.

### Embedded libraries

Many bundles carry libraries inside: inlined packages, jars on the `Bundle-ClassPath`, shaded
code. A scanner that sees only the bundle misses them. The exporter finds them through

- `META-INF/maven/**/pom.properties` of other artifacts (also under `OSGI-OPT/src`),
- jars on the `Bundle-ClassPath`,
- for bundles built in the same workspace: `-buildpath` entries whose classes were inlined
  with `-conditionalpackage`, `Private-Package` or `-includeresource @...`.

Each is listed as a component of its own with its original Maven coordinates, so scanners
match CVEs against it. `osgi:embedded:in` names the bundle, and the bundle depends on it in
the dependency graph.

### Dependencies

The dependency graph is computed from the manifests of the resolved bundles: every requirement
the resolver acts on (`Import-Package`, `Require-Bundle`, `Fragment-Host`, `Require-Capability`)
is matched against what the other components provide. A depends on B because B provides what A
requires. Only the checked-in `-runbundles` are used, nothing is resolved anew. The
application depends on the bundles its `-runrequires` name, on the framework and, at `medium`,
on Java SE.

The SBOM states that the graph is **incomplete** (CycloneDX `compositions`, SPDX
`completeness`), and why, as known unknowns (`osgi:known-unknown`):

- packages from the JDK (system packages, boot delegation) have no edge of their own,
- `DynamicImport-Package` is not resolved,
- every component whose jar, manifest or POM could not be read.

### Licences (`medium`)

Licences are written as SPDX ids or expressions only when they can be told with confidence:

1. `Bundle-License`: ids, expressions, known names and licence URLs,
2. the artifact's POM next to the jar or inside it,
3. a licence file in the jar.

An unrecognised `Bundle-License` (e.g. ANTLR's `https://www.antlr.org/license.html`) does not
end the search: if the POM names the licence as SPDX, that id is used. The URL a licence was
declared with is kept (CycloneDX `license.url`, SPDX `seeAlsos`). What stays unrecognised is
written as free text, never as a guessed id. Several licences are joined with `AND`, because
`Bundle-License` does not say whether they apply together or as alternatives.

### Origin

For every bundle the repository it came from (`osgi:repository:name`, `osgi:repository:kind`:
`maven`, `p2`, `osgi`, `file`, `workspace`) and, where the repository knows it, the download URL
as `distribution` reference.

## BSI TR-03183-2

The German Federal Office for Information Security (BSI) defines in TR-03183-2 which fields an
SBOM must have. It is also the most concrete reading of the SBOM requirement of the EU Cyber
Resilience Act. `level=medium` writes every required field of v2.1.0. There is no separate
"bsi" mode.

### Checklist

1. Set vendor, contact and licence in `cnf/build.bnd` (see [Creator](#creator-bsi-tr-03183-2)).
2. Use CycloneDX, or SPDX 3.0.1.
3. Say whether the framework is shipped (`framework=delivered` is the default).
4. Turn on the check:

   ```
   -sbom: level=medium, validate=bsi-tr-03183-2
   ```

5. Export and read the warnings. Fix them, then consider `validate.strict=true` so that a new
   gap fails the build.

### How the fields are mapped

| TR field | CycloneDX | SPDX 3.0.1 |
|---|---|---|
| Creator of the SBOM (§5.2.1) | `metadata.manufacturer` (email or URL) | `CreationInfo.createdBy` → `Organization` with an `email` or `urlScheme` identifier |
| Timestamp | `metadata.timestamp` | `CreationInfo.created` |
| Component creator | `manufacturer` | `originatedBy` → `Organization` |
| Name, version | `name`, `version` | `name`, `software_packageVersion` |
| File name | `bsi:component:filename` | `software_File.name` via `hasDistributionArtifact` |
| Dependencies and their completeness | `dependencies`, `compositions` | `dependsOn`, `contains` with `completeness` |
| Distribution licence | `licenses` with `acknowledgement: concluded` | `hasConcludedLicense` |
| SHA-512 of the deployable file | `hashes` and `externalReferences[distribution].hashes` | `software_File.verifiedUsing` |
| Executable, archive, structured | `bsi:component:executable`, `…archive`, `…structured` | `software_additionalPurpose`: `executable`, `archive`, `container` or `firmware` |
| Other identifiers | `purl` | `packageUrl` identifier |

The `bsi:*` names are the official
[BSI CycloneDX property taxonomy](https://github.com/BSI-Bund/tr-03183-cyclonedx-property-taxonomy).

### Delivered or not: exact and minimum versions

The TR has **no version ranges**. A component you ship carries its exact version. A component
outside your delivery, which the operator provides, carries the **minimum version** the
application needs. OSGi's import ranges stay out of the SBOM; their lower bound is what the TR
calls the minimum.

| Component | Delivered? | Version | Required fields |
|---|---|---|---|
| Run bundles, embedded jars | yes | exact | all: creator, name, version, file name, licence, SHA-512, file properties |
| Framework and `-runpath` with `framework=delivered` | yes | exact | all |
| Framework and `-runpath` with `framework=provided` | no | minimum | creator, name, version |
| Java SE | no | minimum | creator, name, version |
| Libraries shaded into a bundle without a file of their own | part of the bundle | exact | creator, name, version |

### Java SE is a standard

The Java runtime is not shipped: the operator installs one, of any vendor. So the SBOM does not
name a runtime. It lists the **Java SE platform standard** as a logical component:

```json
{
  "bom-ref": "JavaSE@21.0.0",
  "type": "platform",
  "name": "JavaSE",
  "version": "21.0.0",
  "manufacturer": { "name": "Java Community Process", "url": [ "https://jcp.org" ] },
  "description": "Java SE platform standard (osgi.ee=JavaSE), at least version 21.0.0; not delivered: the Java runtime implementing it is chosen by the operator",
  "properties": [
    { "name": "osgi:ee", "value": "JavaSE" },
    { "name": "osgi:delivery", "value": "provided" },
    { "name": "osgi:version:kind", "value": "minimum" }
  ]
}
```

- **Version**: `-runee` (the environment the application was resolved, and so tested,
  against), else the highest minimum the bundles require (`Require-Capability: osgi.ee`,
  `Bundle-RequiredExecutionEnvironment`).
- **Creator**: the body that specifies the standard, the Java Community Process.
- **No PURL or CPE**: they would name one vendor's runtime.
- Every bundle that requires an execution environment depends on it.

### The check

`validate=bsi-tr-03183-2` reports one line per gap, as a bnd warning, prefixed with
`BSI TR-03183-2:`:

```
warning: BSI TR-03183-2: SBOM and application: no creator (email address or URL); set Bundle-ContactAddress or Bundle-DocURL in the project of the .bndrun, or 'creator' in -sbom
warning: BSI TR-03183-2: pkg:maven/org.example/lib@1.0.0: missing creator (email address or URL), distribution licence
warning: BSI TR-03183-2: BSI TR-03183-2 requires SPDX 3.0.1 or later; spdx.version=2.3 is written — set spdx.version=3.0.1, or use format=cyclonedx
```

| Finding | What to do |
|---|---|
| no creator of the SBOM | `Bundle-Vendor` and `Bundle-ContactAddress` (or `Bundle-DocURL`) in the project of the bndrun or in `cnf/build.bnd`, or `creator=` in `-sbom` |
| a bundle of the workspace without creator or licence | the same headers in `cnf/build.bnd`; they reach every bundle's manifest |
| a third-party bundle without creator | the bundle's manifest names no vendor contact. Nothing to fix on your side; ask the supplier |
| a third-party bundle without licence | its manifest and POM name no licence the exporter recognises. Check by hand |
| SPDX 2.3 | `spdx.version=3.0.1` or `format=cyclonedx` |
| `level=simple` | `level=medium` |

## Reproducible SBOMs

The same application should produce the same SBOM, so that a diff between two builds shows what
changed and nothing else.

- The serial number (CycloneDX `serialNumber`, SPDX namespace) is derived from the content by
  default (`serialNumber=content`). Exporting an unchanged application twice gives the same
  number; any change to a component, version or file gives a new one.
- Component references (`bom-ref`, SPDX ids) are derived from PURL or `bsn@version`.
- Only the timestamp changes. Fix it for a byte-identical result, e.g. to the commit time:

  ```
  -sbom: level=medium, timestamp=${env;SOURCE_DATE_ISO;2026-01-01T00:00:00Z}
  ```

## Bundles from p2 or OBR repositories

A bundle from a p2 or OBR repository has no verified Maven identity, so it has no PURL and is
marked `osgi:identity:matchability=unverified`. Scanners cannot match it against vulnerability
databases.

If the same bundle is also on Maven Central, give its coordinates:

```
-sbom: \
	level=medium,\
	maven.org.eclipse.emf.ecore=org.eclipse.emf:org.eclipse.emf.ecore,\
	maven.com.google.guava=com.google.guava:guava:33.5.0-jre
```

The component then gets the PURL and `osgi:identity:source=configured`. Without a version the
bundle's `major.minor.micro` is used. Make sure the coordinates really name the same artifact:
a wrong PURL is worse than none.

## Security

The exporter reads artifacts it does not control: bundles, embedded jars, manifests, POMs,
licence files, repository indexes. It treats them as untrusted.

- **Resource limits (CWE-400/409)**: POMs and `pom.properties` are read up to 1 MiB, licence
  texts and `about.html` only their first 256 KiB, embedded jars up to 64 MiB and only their
  metadata entries. An embedded jar that expands beyond 256 MiB is not analysed (zip bomb).
  Hashes are computed while streaming.
- **XML (CWE-611/776)**: POMs are parsed without DTDs, external entities or external access.
- **Published URLs (CWE-200)**: download, VCS and website URLs lose user info, query and
  fragment before they go into the SBOM, so a `user:token@` in a repository URL is not
  published.
- **Broken input (CWE-754)**: a component whose jar, manifest or POM cannot be read stays in
  the SBOM. The failure is a bnd warning and a known unknown in the SBOM.

## Troubleshooting

**No SBOM is written, and bnd reports that it has no exporter for `bnd.sbom`.**
bnd did not load the plugin. Check that `-plugin.sbom` is set where the bndrun sees it, and that
the jar exists at the path when the export runs. With Gradle, the export task must depend on the
task that copies the jar ([Gradle](sbom-gradle.md#1-fetch-the-exporter)).

**`Invalid value 'mediun' for SBOM option 'level'; expected simple, medium, full`, and no SBOM.**
A typo in `-sbom`. The message lists the valid values.

**`Unknown SBOM option 'levle' ... is ignored; known options: ...`**
A warning; the option is ignored. Check the spelling.

**A bundle has no PURL.**
It was built in the workspace, or comes from a p2, OBR or file repository. See
[Identity](#identity-purl-or-not) and [`maven.<bsn>`](#bundles-from-p2-or-obr-repositories).

**A library I know is inside a bundle is missing.**
The exporter finds embedded libraries through their `pom.properties`, the `Bundle-ClassPath`, or
the build path of workspace bundles. Code shaded without any of these leaves no trace.

**The SBOM lists old versions.**
The export does not resolve. Resolve the bndrun first and export again.

**Trivy reports a finding for something that is not in my application.**
Check that you scan the SBOM of the bndrun, not a POM. bnd's generated POMs list every
`-buildpath` entry as a dependency by default. See [Maven scopes](maven-scopes.md).
