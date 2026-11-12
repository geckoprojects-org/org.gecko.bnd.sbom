# bnd update on GitLab CI

`ci/gitlab/bnd-update.gitlab-ci.yml` is a CI template with the hidden job `.bnd-update`. It runs
`ci/bnd-update.sh`, the CI-neutral adapter that Jenkins uses as well, on a pipeline schedule:

1. builds the workspace's own bundles (`PREPARE_COMMAND`, default `./gradlew assemble`), so that
   the bndruns that run them resolve,
2. fetches the `bnd-update` CLI and runs `bnd-update apply`: every update is verified (all
   bndruns resolve, `BUILD_COMMAND` passes), and whatever fails is reverted
   ([docs/bnd-update.md](../../docs/bnd-update.md)),
3. commits the changed `.mvn` index lines and `-runbundles` on the branch `bnd-update/updates`,
   signed off,
4. pushes the branch and opens **one** merge request with the report as its description. On later
   runs it updates that merge request.

The report is also kept as the job artifact `bnd-update-report.md`.

`ci/gitlab/gitlab-ci.example.yml` is a complete `.gitlab-ci.yml` with a build job, the SBOMs as a
CycloneDX report and the bnd update job.

## Setup

| What | How |
|---|---|
| token | a **project access token** (role Developer or higher) with the scopes `api` and `write_repository`, stored as the masked and protected CI/CD variable `GITLAB_TOKEN`. The job token (`CI_JOB_TOKEN`) can neither push nor open merge requests. |
| schedule | *Build > Pipeline schedules*: target branch (e.g. `main`), weekly, variable `BND_UPDATE=true`. A manual pipeline (*Run pipeline*) with `BND_UPDATE=true` works as well. |
| other jobs | the schedule runs the whole pipeline; give the other jobs `rules: - if: '$BND_UPDATE != "true"'` (as the example does) if they should not run then |
| runner | a Docker runner; the job uses `eclipse-temurin:21-jdk` and installs git when it is missing |
| commit identity | `GIT_NAME`/`GIT_EMAIL`, by default the user who owns the schedule or ran the pipeline (`GITLAB_USER_NAME`/`GITLAB_USER_EMAIL`); the `Signed-off-by` line uses them |

The merge request is opened with the token of a project bot, so its pipeline runs as usual and
the update is built and tested before anyone merges it.

## Including the template

Pin both files to a commit of this repository: the template with GitLab's `integrity` check, the
script with its SHA-256. Both run with the token.

```yaml
include:
  - remote: https://raw.githubusercontent.com/geckoprojects-org/org.gecko.bnd.sbom/<commit>/ci/gitlab/bnd-update.gitlab-ci.yml
    integrity: sha256-<base64>

bnd-update:
  extends: .bnd-update
  variables:
    BND_UPDATE_COMMIT: <commit>
    BND_UPDATE_SHA256: <sha256>
```

```
c=<commit>; base=https://raw.githubusercontent.com/geckoprojects-org/org.gecko.bnd.sbom/$c
curl -fsSL $base/ci/gitlab/bnd-update.gitlab-ci.yml | openssl dgst -sha256 -binary | base64   # integrity: sha256-...
curl -fsSL $base/ci/bnd-update.sh | sha256sum                                                  # BND_UPDATE_SHA256
```

`include:remote` with `integrity` needs GitLab 17.9 or later. On older instances, copy the
template into the repository and use `include:local`.

## Configuration

Set these as variables of the job (or of the schedule):

| Variable | Meaning | Default |
|---|---|---|
| `PREPARE_COMMAND` | runs before bnd update; builds the workspace's bundles | `./gradlew assemble --no-daemon` |
| `BUILD_COMMAND` | build that verifies each update; empty: only the resolve check | `./gradlew build -x test --no-daemon` |
| `MODE` | `each` (one by one, keep what passes) or `all` (all or nothing) | `each` |
| `SCOPE` | `micro`, `minor`, `major`; empty: the workspace's `-update-policy` | — |
| `ONLY` | `groupId:artifactId` patterns | all proposed |
| `TRIVY_REPORT`, `SBOM` | apply the fixes for a Trivy report instead | — |
| `BRANCH`, `BASE`, `TITLE`, `LABELS` | of the merge request; `BASE` defaults to the branch the pipeline runs for | `bnd-update/updates`, that branch, `bnd update: dependency updates`, `dependencies` |
| `CLI_VERSION`, `CLI_JAR` | which CLI | `0.1.0-SNAPSHOT` from Maven Central |
| `DRY_RUN` | `true`: apply and commit in the job only, report what would be pushed and requested | `false` |
| `FAIL_ON_REVERTED` | `true`: fail the job when an update had to be reverted | `false` |

## SBOMs in GitLab

A job can hand the CycloneDX SBOMs of the bndruns to GitLab as a report:

```yaml
artifacts:
  reports:
    cyclonedx:
      - "*/generated/sbom/*/*.cdx.json"
```

GitLab then shows the components in its dependency list, and on tiers with dependency scanning
also their known vulnerabilities. Adjust the path to where the workspace's export tasks write
the SBOMs. Which GitLab tiers and CycloneDX versions show what has not been checked on a GitLab
instance yet. Our default output is CycloneDX 1.6.

## Trying it

`DRY_RUN=true` in a manual pipeline applies and commits the updates in the job, and shows
whether a merge request would be opened or updated. Nothing is pushed.
