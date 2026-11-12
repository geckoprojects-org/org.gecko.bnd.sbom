# org.gecko.bnd.sbom

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
- **Layer:** `osgi:layer` says where a component sits — `runbundle` (installed, can be
  updated in the framework), `runfw` or `runpath` (on the framework's class path, replaced only
  by rebuilding the launch). `-runsystempackages` and `-runsystemcapabilities` add no
  components: they only declare exports from `-runfw`, `-runpath` or the JDK; the JDK itself
  is not part of the SBOM.
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
where configured, per library if needed; variants such as guava `-jre`/`-android` are kept.

```
-update-policy: default;scope=micro, com.fasterxml.jackson.core:*;scope=minor
```

**After any update** of a `.mvn` index or a `-buildpath` version — by tool, Bndtools or hand —
**resolve every bndrun** before committing — check with `bnd-update resolve`, write with
`./gradlew resolve`: narrow import ranges can make a
bndrun unresolvable, and an update can change what other bndruns resolve to.

**GitHub Action** `.github/actions/bnd-update` runs `apply` and opens (or updates) one pull
request with the verified updates and the report; this repository runs it on itself weekly.

Exit codes (0 nothing to do, 1 fixes within the policy, 2 something needs a decision), the
fix-version rules, library API, the action's inputs, CI examples for Jenkins, GitLab and GitHub,
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
| `snapshot` | `-SNAPSHOT` bundles to the DIM Nexus (`dim-snapshot`) and the Central Portal snapshot repository |
| `main` | release bundles to the DIM Nexus (`dim-release`) and, signed, to Maven Central |
| any other | build and test |

The mechanics are in `cnf/ext/release.bnd`.

## License

Eclipse Public License 2.0, see `LICENSE`.
