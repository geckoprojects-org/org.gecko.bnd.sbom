# bnd update on Jenkins

Jenkins runs bnd update through `ci/bnd-update.sh`, the CI-neutral adapter that GitLab CI uses as
well. The script

1. fetches the `bnd-update` CLI (a given jar, or a version from Maven Central, checked against the
   repository's checksum),
2. runs `bnd-update apply` — every update is verified: all bndruns resolve, the build passes;
   what fails is reverted ([docs/bnd-update.md](../../docs/bnd-update.md)),
3. commits the changed `.mvn` index lines and `-runbundles` on a branch, signed off,
4. pushes the branch and opens — or, on later runs, updates — **one** pull request (GitHub) or
   merge request (GitLab), with the report as its description.

`ci/jenkins/Jenkinsfile.example` is a complete pipeline; usually only its `bnd update` stage is
merged into an existing `Jenkinsfile`.

## Setup

| What | How |
|---|---|
| Java 21 | `tools { jdk 'OpenJDK21' }` (the name of the JDK installation in Jenkins) |
| bash, git, curl | on the agent |
| built workspace | `./gradlew assemble` before the script — bndruns that run the workspace's own bundles only resolve when those exist |
| GitHub token | a *Secret text* credential with a fine-grained token: *Contents* and *Pull requests* read/write on the repository; passed as `GITHUB_TOKEN`, plus `GITHUB_REPOSITORY=owner/repo` |
| GitLab token | a project access token with `api` and `write_repository`; passed as `GITLAB_TOKEN`, plus `CI_PROJECT_ID`, `CI_PROJECT_PATH`, `CI_API_V4_URL`, `CI_SERVER_URL` (outside GitLab CI they are not set automatically) |
| commit identity | `GIT_NAME`, `GIT_EMAIL` (the `Signed-off-by` line uses them, for DCO checks) |
| schedule | `triggers { cron(...) }`, guarded to the target branch; `UserIdCause` allows running it by hand |

Unlike a pull request opened with GitHub Actions' `GITHUB_TOKEN`, one opened with a personal or
app token **does** start the repository's workflows, so the pull request gets its usual checks.

## Getting the script

Pin it: download `ci/bnd-update.sh` from a fixed commit of this repository and check its SHA-256,
as the example does — the script runs with the token. Alternatively copy it into the repository.

```
curl -fsSL -o bnd-update.sh https://raw.githubusercontent.com/geckoprojects-org/org.gecko.bnd.sbom/<commit>/ci/bnd-update.sh
sha256sum bnd-update.sh     # take this value into BND_UPDATE_SHA256
```

## Configuration

All through the environment, see the header of `ci/bnd-update.sh`:

| Variable | Meaning | Default |
|---|---|---|
| `MODE` | `each` (one by one, keep what passes) or `all` (all or nothing) | `each` |
| `SCOPE` | `micro`, `minor`, `major`; empty: the workspace's `-update-policy` | — |
| `ONLY` | `groupId:artifactId` patterns | all proposed |
| `TRIVY_REPORT`, `SBOM` | apply the fixes for a Trivy report instead | — |
| `BUILD_COMMAND` | build that verifies each update | none |
| `BRANCH`, `BASE`, `TITLE`, `LABELS` | of the request; `BASE` defaults to `CHANGE_TARGET`/`BRANCH_NAME` on Jenkins | `bnd-update/updates`, branch, `bnd update: dependency updates`, `dependencies` |
| `DRY_RUN` | `true`: apply and commit locally, only report what would be pushed and requested | `false` |
| `FAIL_ON_REVERTED` | `true`: fail the stage when an update had to be reverted | `false` |

The report is also written to `bnd-update-report.md` in the workspace for `archiveArtifacts`.

## Trying it

```
DRY_RUN=true GITHUB_TOKEN=... GITHUB_REPOSITORY=owner/repo BASE=main bash ci/bnd-update.sh
```

applies and commits the updates in the local checkout and shows whether it would open a new pull
request or update the existing one — nothing is pushed.
