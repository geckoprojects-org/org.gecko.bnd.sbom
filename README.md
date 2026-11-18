# org.gecko.bnd.sbom

[![CI Build](https://github.com/geckoprojects-org/org.gecko.bnd.sbom/actions/workflows/build.yml/badge.svg?branch=snapshot)](https://github.com/geckoprojects-org/org.gecko.bnd.sbom/actions/workflows/build.yml?query=branch%3Asnapshot)
[![CodeQL](https://github.com/geckoprojects-org/org.gecko.bnd.sbom/actions/workflows/codeql.yml/badge.svg?branch=snapshot)](https://github.com/geckoprojects-org/org.gecko.bnd.sbom/actions/workflows/codeql.yml?query=branch%3Asnapshot)
[![SBOM and Trivy](https://github.com/geckoprojects-org/org.gecko.bnd.sbom/actions/workflows/sbom.yml/badge.svg?branch=snapshot)](https://github.com/geckoprojects-org/org.gecko.bnd.sbom/actions/workflows/sbom.yml?query=branch%3Asnapshot)
[![Snapshot](https://img.shields.io/maven-metadata/v?metadataUrl=https%3A%2F%2Fcentral.sonatype.com%2Frepository%2Fmaven-snapshots%2Forg%2Fgeckoprojects%2Fbnd%2Forg.gecko.bnd.sbom%2Fmaven-metadata.xml&label=snapshot)](https://central.sonatype.com/repository/maven-snapshots/org/geckoprojects/bnd/org.gecko.bnd.sbom/)
[![Java 21](https://img.shields.io/badge/Java-21-blue.svg)](https://adoptium.net/)
[![License: EPL-2.0](https://img.shields.io/badge/License-EPL--2.0-blue.svg)](LICENSE)

A bnd exporter plugin that writes a Software Bill of Materials (SBOM) for the **resolved OSGi
application** of a `.bndrun`: the resolved `-runbundles` plus the framework layer (`-runfw`,
`-runpath`). Output formats are CycloneDX 1.6 and SPDX 2.3 (JSON).

| | |
|---|---|
| Maven coordinates | `org.geckoprojects.bnd:org.gecko.bnd.sbom` |
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
| `level` | `simple` (name, version, PURL), `medium` (adds hashes, licenses and the fields of BSI TR-03183-2, see below), `full` | `simple` |
| `format` | `cyclonedx`, `spdx` | `cyclonedx` |
| `includeOSGIMetadata` | `true`, `false` | `false` |
| `timestamp` | ISO-8601 instant, e.g. `2026-01-01T00:00:00Z`, for reproducible builds | time of the export |
| `serialNumber` | `content` (derived from format, level, application and components: an unchanged application keeps its serial number), `random` | `content` |
| `application.name`, `application.group`, `application.version` | identity of the application in the metadata | bndrun name, `-groupid`, `Bundle-Version` (with a `-groupid` in Maven form, `0.1.1.SNAPSHOT` → `0.1.1-SNAPSHOT`, as in the components' PURLs) |
| `cyclonedx.version` | `1.6`, `1.7` (written with the matching `$schema`) | `1.6` |
| `application.purl` | PURL of the application, e.g. of the image built from the bndrun (`"pkg:oci/..."`, quoted); also its `bom-ref` | none: the application is not published under the workspace's Maven coordinates, so none is derived from them |
| `property.<name>` | free properties of the BOM, e.g. `property.vcs:commit=${env;GITHUB_SHA}`; CycloneDX `metadata.properties`, SPDX document comment | none |
| `creator` | creator of the SBOM and of the application, an email address or an http(s) URL (BSI TR-03183-2 §5.2.1); CycloneDX `metadata.manufacturer` | at `medium` from the project the `.bndrun` lives in: `Bundle-Vendor` as name, an email address from `Bundle-ContactAddress`, else a URL from there or `Bundle-DocURL` |
| `validate` | `bsi-tr-03183-2`: checks the SBOM against the required fields of BSI TR-03183-2 v2.1.0 and reports each gap; the SBOM is written either way | none |
| `validate.strict` | `true`: a gap found by `validate` is an error, which fails the build; `false`: a warning | `false` |
| `framework` | whether the OSGi framework (`-runfw`, together with its class path `-runpath`) is part of the scope of delivery: `delivered` for an application that ships with its framework; `provided` for a library, or a test setup, that runs on whichever framework the user installs — the framework and the `-runpath` entries are then identified with the version it was resolved against as minimum (`osgi:delivery=provided`, `osgi:version:kind=minimum`), without filename or hash. A `.bndrun` does not tell which of the two it is | `delivered` |
| `maven.<bsn>` | `groupId:artifactId[:version]`: Maven coordinates for a bundle from a p2 or OBR repository that is also published to Maven (version defaults to the bundle's major.minor.micro) | none |

### BSI TR-03183-2

`level=medium` writes the fields BSI TR-03183-2 v2.1.0 requires, CycloneDX-side with the
[BSI property taxonomy](https://github.com/tr-03183/tr-03183-cyclonedx-property-taxonomy):

- per bundle: `bsi:component:filename` and the properties `bsi:component:executable`,
  `bsi:component:archive`, `bsi:component:structured` (a jar: executable, archive, structured),
  next to the SHA-512 hash and the licenses;
- the component creator as `manufacturer`: `Bundle-Vendor` as name, an email address from
  `Bundle-ContactAddress`, else the URL there or in `Bundle-DocURL`;
- the creator of the SBOM and of the application: the vendor of the bnd project the `.bndrun`
  lives in, from the same headers in its `bnd.bnd` (a `.bndrun` does not inherit them from
  there, so the exporter looks the project up), else from the `.bndrun` and the workspace. The
  tool, bnd, is listed under `metadata.tools`, not as creator;
- the Java SE API as a logical component (CycloneDX type `platform`, name of the `osgi.ee`
  capability, e.g. `JavaSE`). The Java runtime is not delivered — the operator chooses one of any
  vendor — so the component stands for the API, without PURL or CPE, and its version is the
  minimum the application requires (TR §3.2.1), marked `osgi:version:kind=minimum`: the
  `-runee`, or else the highest minimum the bundles require. Java SE is a standard, so its
  creator is the body that specifies it, the Java Community Process (`https://jcp.org`), not
  the vendor of a runtime. Every bundle that requires an execution environment depends on it;
- the scope of delivery of the framework, which only the author knows: an application ships
  with its framework (`framework=delivered`, the default), a library runs on the user's
  (`framework=provided`); a provided framework, together with its class path (`-runpath`), is
  identified like the Java SE standard, with
  its minimum version and without filename, hash or file properties.

TR-03183-2 has no version ranges: delivered components carry their exact, resolved version,
components outside the delivery their minimum version.

`validate=bsi-tr-03183-2` reports what is still missing, e.g. a bundle without creator or license.
The TR requires SPDX 3.0.1 or later; `format=spdx` currently writes SPDX 2.3, so use
`format=cyclonedx` for a conformant SBOM.

```
-sbom: level=medium, creator=security@example.org, validate=bsi-tr-03183-2
```

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
- **Layer:** `osgi:layer` says where a component sits — `runbundle` (installed, can be
  updated in the framework), `runfw` or `runpath` (on the framework's class path, replaced only
  by rebuilding the launch). `-runsystempackages` and `-runsystemcapabilities` add no
  components: they only declare exports from `-runfw`, `-runpath` or the JDK; the JDK itself
  appears only at `medium`, as the Java SE standard (see BSI TR-03183-2 below).
- **Licenses** (`medium`): as SPDX ids where they can be told with confidence — from
  `Bundle-License` (ids, expressions, known names and URLs), the artifact's POM next to the
  jar or inside it, or a license file. A `Bundle-License` that is not recognized, e.g. a URL
  like ANTLR's `https://www.antlr.org/license.html`, does not end the search: if a POM names
  the license as SPDX, that id is used. The URL a license was declared with is kept
  (CycloneDX `license.url`, SPDX `seeAlsos`); what stays unrecognized is written as free text,
  never as a guessed id.
- **Origin:** for every bundle the repository it was taken from (`osgi:repository:name`,
  `osgi:repository:kind`: `maven`, `p2`, `osgi`, `file`, `workspace`) and, where the
  repository knows it, the download URL as `distribution` reference.

## Security

The exporter reads artifacts it does not control — bundles, embedded jars, manifests, POMs,
license files, repository indexes. It is written to treat them as untrusted:

- **Resource limits (CWE-400/409):** POMs and `pom.properties` are read up to 1 MiB, license
  texts and `about.html` only their first 256 KiB, embedded jars up to 64 MiB and only their
  metadata entries; an embedded jar that expands beyond 256 MiB is not analysed (zip bomb).
  Hashes are computed while streaming.
- **XML (CWE-611/776):** POMs are parsed without DTDs, external entities or external access.
- **Published URLs (CWE-200):** download, VCS and website URLs lose user info, query and
  fragment before they go into the SBOM, so a `user:token@` in a repository URL is not
  published.
- **Broken input (CWE-754):** a component whose jar, manifest or POM cannot be read stays in
  the SBOM; the failure is a bnd warning and a known unknown in the BOM.
- **CI:** CodeQL (`security-extended`) runs on every pull request and weekly; the Gradle wrapper
  and the Python packages of the schema check are verified by SHA-256.

## bnd update: newer versions and vulnerability fixes

`org.gecko.bnd.update` (library) and `org.gecko.bnd.update.cli` (executable jar) answer three
questions for a bnd workspace and apply updates — only `apply` changes files:

| Command | Question | Proposal |
|---|---|---|
| `updates` | Which libraries in the `.mvn` indexes have newer versions? | the highest version the version policy allows |
| `vulnerabilities --trivy FILE [--sbom FILE]` | Which vulnerable libraries (Trivy report) can be fixed with what the repositories offer? | the smallest allowed version that fixes all of the library's vulnerabilities |
| `resolve` | Does every bndrun still resolve — and to what? | per bndrun: unchanged, changed (bundles added/removed) or the unresolved requirements |
| `apply` | **changes the workspace:** applies updates (all, `--only` some, or `--from-vulnerabilities`) | the `.mvn` lines changed in place, every bndrun resolved, new `-runbundles` written, `--build-command` run; what fails is reverted (`--mode all` all or nothing, `each` one by one) |

```
java -jar org.gecko.bnd.update.cli.jar updates --format markdown
java -jar org.gecko.bnd.update.cli.jar vulnerabilities --trivy trivy.json --sbom app.bndrun.cdx.json
```

**Version policy:** only `micro` updates (same major.minor) by default; `minor` or `major` only
where configured, per library if needed; variants such as guava `-jre`/`-android` or byte-buddy
`-jdk5` are kept, date versions (`20040616`) are not taken for updates. Indexes a bnd `-library`
brings along are reported with that library as origin, but never written; an entry another index
outranks is reported as shadowed, not as an update. Build-time libraries (in no application
bndrun: tests, build path, the bnd toolchain itself) are listed separately with their latest
version and can get their own scope (`buildtime;scope=minor`).

```
-update-policy: default;scope=micro, com.fasterxml.jackson.core:*;scope=minor
```

**After any update** of a `.mvn` index or a `-buildpath` version — by tool, Bndtools or hand —
**resolve every bndrun** before committing — check with `bnd-update resolve`, write with
`./gradlew resolve`: narrow import ranges can make a
bndrun unresolvable, and an update can change what other bndruns resolve to.

**GitHub Action** `.github/actions/bnd-update` runs `apply` and opens (or updates) one pull
request with the verified updates and the report; this repository runs it on itself weekly.
For Jenkins (and GitLab CI) `ci/bnd-update.sh` does the same with plain bash, git, curl and Java:
see [ci/jenkins/README.md](ci/jenkins/README.md) and, for GitLab CI with a ready-made template,
[ci/gitlab/README.md](ci/gitlab/README.md). For Maven projects: the SBOM comes from
`bnd-export-maven-plugin` with this exporter, the fixes from `bnd-update-maven-plugin`
(goal `vulnerabilities`) — runnable in [examples/maven-sbom](examples/maven-sbom/README.md).
**Examples** for Gradle, Maven and Jenkins, with SBOM, Trivy and fixes: [examples/](examples/README.md).
For Gradle builds, the plugin `org.geckoprojects.bnd.update` adds the tasks `bndUpdates`,
`bndVulnerabilities`, `bndResolveCheck` and `bndApply`.

Exit codes (0 nothing to do, 1 fixes within the policy, 2 something needs a decision), the
fix-version rules, library API, Maven and Gradle plugins, the action's inputs, CI examples for Jenkins, GitLab and GitHub,
limits: [docs/bnd-update.md](docs/bnd-update.md).

## Maven scopes in bnd-generated POMs

bnd writes a `pom.xml` into every released bundle and, by default, turns **every `-buildpath`
entry into a `compile` dependency**. That POM is what Maven and Gradle consumers resolve — and
what SBOM tools read: Trivy takes `compile` and `runtime` dependencies from a POM, also
transitively from the published POMs of dependencies, and leaves out `provided`, `test` and
optional ones. A bundle that lists annotation jars, framework APIs or libraries it carries
inside as `compile` makes every consumer's SBOM larger than the software that runs, and their
vulnerability scans report findings for artifacts that are not there.

The SBOM written by this exporter is not affected (it comes from the resolved `-runbundles`),
but everyone who consumes our bundles through Maven or Gradle is. So in bnd workspaces we
apply three rules:

| What is on the build path | Rule | Why |
|---|---|---|
| Annotations (`org.osgi.annotation.*`, DS/metatype annotations, `biz.aQute.bnd.annotation`) and specification APIs provided by the framework (`osgi.core`, `org.osgi.framework`) | `maven-scope=provided` | Annotations do not exist at runtime; framework APIs come from the framework. The consumer's runtime has them. |
| Libraries inlined into the bundle (`-conditionalpackage`, `Private-Package`, `-includeresource @lib.jar!/...`) | `maven-optional=true` | They are part of the bundle, not a dependency; bnd leaves them out of the POM. This SBOM still lists them as embedded components. |
| Libraries the bundle needs installed next to it at runtime (EMF, Jackson, ...) | `compile` (default) | Real dependencies; consumers must get them and their SBOMs must list them. |

```
-buildpath: \
	org.osgi.annotation.versioning;maven-scope=provided,\
	osgi.core;maven-scope=provided,\
	org.osgi.util.promise;maven-optional=true,\
	org.eclipse.emf.ecore

-conditionalpackage: org.osgi.util.*
```

A project whose whole build path is provided by its runtime sets the default instead:
`-maven-scope: provided` (this plugin does: bnd is its runtime). Shared entries belong in the
workspace library, so one change fixes every project.

Details, examples and how to check a generated POM: [docs/maven-scopes.md](docs/maven-scopes.md).

## Build

Requires Java 21. The workspace uses bnd 7.4.0 and Gradle 9 (wrapper included).

```
./gradlew build
```

## Release

Publishing is done by Jenkins (`Jenkinsfile`); GitHub Actions only builds and tests.

| Branch | Result |
|---|---|
| `snapshot` | `-SNAPSHOT` bundles and plugins to the DIM Nexus (`dim-snapshot`) and the Central Portal snapshot repository |
| `main` | release bundles and plugins to the DIM Nexus (`dim-release`) and, signed, to Maven Central |
| any other | build and test |

The mechanics are in `cnf/ext/release.bnd`; the Maven and Gradle plugins, built outside the bnd
workspace, are published by `ci/publish-plugins.sh` with the same version
([docs/bnd-update.md](docs/bnd-update.md#publishing-the-plugins)).

## License

Eclipse Public License 2.0, see `LICENSE`.
