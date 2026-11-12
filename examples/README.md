# Examples

Runnable examples for the SBOM exporter and bnd update, per build tool and CI system. CI of this
repository builds them on every change.

| Your build | Example | SBOM | Updates and fixes | CI |
|---|---|---|---|---|
| **bnd workspace with Gradle** | [gradle-workspace](gradle-workspace/README.md) | `./gradlew sbom` (bnd `Export` task with the exporter) | Gradle plugin `org.geckoprojects.bnd.update`: `bndUpdates`, `bndVulnerabilities`, `bndResolveCheck`, `bndApply` | [Jenkinsfile](gradle-workspace/Jenkinsfile) |
| **Maven with the bnd Maven plugins** | [maven-sbom](maven-sbom/README.md) | `bnd-export-maven-plugin` with the exporter as plugin dependency | `bnd-update-maven-plugin`, goal `vulnerabilities` | [Jenkinsfile](maven-sbom/Jenkinsfile) |

Update pull/merge requests from CI, for a bnd workspace:

| CI | How | Documentation |
|---|---|---|
| Jenkins | `ci/bnd-update.sh`, a stage in the Jenkinsfile (weekly) | [ci/jenkins/README.md](../ci/jenkins/README.md), the `bnd update` stage of [gradle-workspace/Jenkinsfile](gradle-workspace/Jenkinsfile) |
| GitLab CI | template `ci/gitlab/bnd-update.gitlab-ci.yml` (pipeline schedule) | [ci/gitlab/README.md](../ci/gitlab/README.md) |
| GitHub Actions | composite action `.github/actions/bnd-update` | [docs/bnd-update.md](../docs/bnd-update.md#github-action) |

The examples use the `-SNAPSHOT` versions from the Central Portal's snapshot repository until the
first release; then the versions in `build.gradle`/`pom.xml` change to the release.

Background: the SBOM ([README](../README.md)), bnd update ([docs/bnd-update.md](../docs/bnd-update.md)),
Maven scopes in bnd-generated POMs ([docs/maven-scopes.md](../docs/maven-scopes.md)).
