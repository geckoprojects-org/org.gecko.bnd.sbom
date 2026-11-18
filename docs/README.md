# Documentation

This repository contains two tools for OSGi applications built with
[bnd](https://bnd.bndtools.org/):

- the **SBOM exporter** writes a Software Bill of Materials of the resolved application of a
  `.bndrun`, in CycloneDX or SPDX, complete enough for the EU Cyber Resilience Act and BSI
  TR-03183-2;
- **bnd update** finds newer versions and vulnerability fixes for the libraries of a bnd
  workspace, applies them, and proves them by resolving every bndrun and building the workspace.

They work together: the exporter writes the SBOM, Trivy scans it, bnd update proposes and
applies the fixes.

```
.bndrun ──► SBOM exporter ──► app.bndrun.cdx.json ──► Trivy ──► trivy.json ──► bnd update ──► fix versions
                                                                                          └──► pull/merge request
```

## Where to start

| I want to … | Read |
|---|---|
| understand what the SBOM contains and configure it | [SBOM exporter: reference](sbom-exporter.md) |
| write SBOMs in a bnd workspace built with Gradle | [SBOMs with Gradle](sbom-gradle.md) |
| write SBOMs in a Maven project | [SBOMs with Maven](sbom-maven.md) |
| scan SBOMs and publish them in CI | [SBOMs in CI](sbom-ci.md) |
| meet BSI TR-03183-2 / the CRA | [SBOM exporter: BSI TR-03183-2](sbom-exporter.md#bsi-tr-03183-2) |
| understand bnd update, its version policy and command line | [bnd update](bnd-update.md) |
| use bnd update in a Gradle build | [bnd update with Gradle](bnd-update-gradle.md) |
| use bnd update in a Maven build | [bnd update with Maven](bnd-update-maven.md) |
| get weekly update pull/merge requests on GitHub, GitLab or Jenkins | [bnd update in CI](bnd-update-ci.md) |
| keep the POMs of my bundles from bloating my users' SBOMs | [Maven scopes in bnd-generated POMs](maven-scopes.md) |
| try everything in a working example | [examples](../examples/README.md) |
| build or release this repository | [Developing](development.md) |

## The pieces

| Piece | Maven coordinates | What it is | Documentation |
|---|---|---|---|
| SBOM exporter | `org.geckoprojects.bnd:org.gecko.bnd.sbom` | bnd exporter plugin, export type `bnd.sbom` | [reference](sbom-exporter.md), [Gradle](sbom-gradle.md), [Maven](sbom-maven.md), [CI](sbom-ci.md) |
| bnd update library | `org.geckoprojects.bnd:org.gecko.bnd.update` | Java API | [Using it as a library](bnd-update.md#using-it-as-a-library) |
| bnd update CLI | `org.geckoprojects.bnd:org.gecko.bnd.update.cli` | executable jar, bnd included | [Command line](bnd-update.md#command-line) |
| Gradle plugin | plugin id `org.geckoprojects.bnd.update` | tasks `bndUpdates`, `bndVulnerabilities`, `bndResolveCheck`, `bndApply` | [bnd update with Gradle](bnd-update-gradle.md) |
| Maven plugin | `org.geckoprojects.bnd:bnd-update-maven-plugin` | goal `vulnerabilities` | [bnd update with Maven](bnd-update-maven.md) |
| GitHub Action | `geckoprojects-org/org.gecko.bnd.sbom/.github/actions/bnd-update` | update pull requests | [bnd update in CI](bnd-update-ci.md#github-actions) |
| CI adapter | `ci/bnd-update.sh` | update pull/merge requests from Jenkins, GitLab CI or a shell | [bnd update in CI](bnd-update-ci.md#jenkins-and-gitlab-ci-the-ci-adapter) |
| GitLab template | `ci/gitlab/bnd-update.gitlab-ci.yml` | the CI adapter as GitLab job | [bnd update in CI](bnd-update-ci.md#gitlab-ci) |

Until the first release, all artifacts are `0.1.0-SNAPSHOT` in the Central Portal's snapshot
repository (`https://central.sonatype.com/repository/maven-snapshots/`).

## A complete setup in five steps

For a bnd workspace built with Gradle and hosted on GitHub:

1. **Vendor and licence** in `cnf/build.bnd`:

   ```
   Bundle-Vendor: Example Org
   Bundle-ContactAddress: security@example.org
   Bundle-License: Apache-2.0;link="https://www.apache.org/licenses/LICENSE-2.0"
   -update-policy: default;scope=micro, buildtime;scope=minor
   ```

2. **The SBOM** of each application bndrun: fetch the exporter, register it, add an export task
   ([SBOMs with Gradle](sbom-gradle.md)):

   ```
   -plugin.sbom: org.gecko.bnd.sbom.SbomExporter;path:="${workspace}/cnf/cache/sbom-exporter/org.gecko.bnd.sbom.jar"
   -sbom: level=medium, validate=bsi-tr-03183-2
   ```

3. **The Gradle plugin** for bnd update ([bnd update with Gradle](bnd-update-gradle.md)):

   ```groovy
   plugins { id 'org.geckoprojects.bnd.update' version '<version>' }
   bndUpdate { sbom = file('app/generated/sbom/app.bndrun.cdx.json') }
   ```

4. **On every build and daily**: export, Trivy, `bndVulnerabilities`, results in the run summary
   and the Security tab ([SBOMs in CI](sbom-ci.md#github-actions)).

5. **Weekly**: the GitHub Action applies the updates the policy allows, one by one, verified by
   resolving and building, and opens one pull request
   ([bnd update in CI](bnd-update-ci.md#github-actions)).

The same for GitLab CI and Jenkins is on the same pages.
