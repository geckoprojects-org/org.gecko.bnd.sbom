# bnd update in CI: GitHub Actions, GitLab CI, Jenkins

[bnd update](bnd-update.md) is most useful when it runs by itself: a report with the fix
versions on every build, and once a week **one** pull or merge request with every update that
passed. This page shows the setup for GitHub Actions, GitLab CI and Jenkins, and what to
consider.

**Contents**

- [Two jobs](#two-jobs)
- [Recommendations](#recommendations)
- [GitHub Actions](#github-actions)
- [Jenkins and GitLab CI: the CI adapter](#jenkins-and-gitlab-ci-the-ci-adapter)
- [Jenkins](#jenkins)
- [GitLab CI](#gitlab-ci)
- [Reviewing an update request](#reviewing-an-update-request)
- [Troubleshooting](#troubleshooting)

## Two jobs

| Job | When | What | Result |
|---|---|---|---|
| **Report** | every build, and daily | export the SBOM, scan it with Trivy, run `vulnerabilities` | the fix version for each finding, in the build summary or as artifact; the build is marked when something needs a decision |
| **Update** | weekly, and on demand | run `apply`: every update (or the fixes of a Trivy report) is applied, resolved and built one by one; what fails is reverted | one pull/merge request with the verified updates and the report as description; later runs update it |

The report job is described in [SBOMs in CI](sbom-ci.md). This page is about the update job.

What the update job does, on every CI:

1. builds the workspace's own bundles (`./gradlew assemble`), so that the bndruns that run them
   resolve,
2. fetches the bnd update CLI (pinned version, checked against its checksum),
3. runs `bnd-update apply`: per update, the `.mvn` line is changed, every bndrun is resolved, the
   new `-runbundles` are written, the build command runs; what fails is reverted,
4. commits the result on a branch (`bnd-update/updates`), signed off,
5. pushes the branch and opens a pull/merge request, or updates the one that is already open, so
   that repeated runs do not pile up requests,
6. puts the report into the request's description and the job summary.

## Recommendations

| Topic | Recommendation | Why |
|---|---|---|
| Schedule | weekly, on the default branch, plus manual runs | small, regular steps are easier to review than a big one per quarter; weekly is often enough for micro updates |
| Mode | `each` | one failing update does not hold back the others; the report says which one failed and why |
| Build command | `./gradlew build -x test` (or with tests, if they are fast) | resolving proves that the bndruns are consistent, the build that the code compiles; the full test suite runs on the request anyway |
| Version policy | `default;scope=micro, buildtime;scope=minor` in `cnf/build.bnd`; wider scopes only per library | bug-fix releases are the safe default; tests and build tools never reach the application |
| One request | always the same branch (`bnd-update/updates`) | later runs update the open request instead of opening new ones |
| Fixes separately | a second job with `trivy-report`/`TRIVY_REPORT`, branch `bnd-update/fixes`, title `bnd update: vulnerability fixes` | security fixes can be reviewed and merged faster than routine updates |
| Token | a GitHub App token, a fine-grained token, or a GitLab project access token, never a personal admin token | the request should get the normal CI checks (see below), and the token should be able to do nothing else |
| CI on the request | make sure the pipeline runs on the request | `apply` proves resolving and building, not that the application behaves: the OSGi tests must run |
| Pinning | pin the action, the script and the CLI to a commit or version, with a checksum | the job runs with a write token |
| Commits | signed off (`Signed-off-by`), as the adapters do | DCO checks pass |
| Reverted updates | `fail-on-reverted: false` (default), read the report | a reverted update usually needs a human; failing the job does not make it faster. Turn it on if nobody reads the reports |
| Concurrency | one update job at a time (`concurrency`, `disableConcurrentBuilds`, `resource_group`) | two runs would push to the same branch |
| Cache | cache `~/.m2/repository` | bnd downloads every library's metadata; Maven Central rate-limits CI runners that fetch everything on every run (HTTP 429) |

## GitHub Actions

`.github/actions/bnd-update` is a composite action. It fetches the CLI (or uses a given jar), runs
`apply`, writes the report into the job summary and the pull request description, and opens the
pull request, or updates it when the branch already has one.

### Weekly updates

`.github/workflows/bnd-update.yml`:

```yaml
name: bnd update

on:
  schedule:
    - cron: '23 5 * * 2'        # weekly, Tuesday 05:23 UTC
  workflow_dispatch:
    inputs:
      scope:
        description: Default scope for this run (micro, minor, major)
        default: micro

permissions:
  contents: read

concurrency:
  group: bnd-update
  cancel-in-progress: false

jobs:
  update:
    runs-on: ubuntu-latest
    permissions:
      contents: write          # push the update branch
      pull-requests: write     # open the pull request
    steps:
      - uses: actions/checkout@<sha>
      - uses: actions/setup-java@<sha>
        with:
          distribution: temurin
          java-version: '21'
      - uses: gradle/actions/setup-gradle@<sha>

      # the workspace's own bundles: bndruns that run them only resolve when they are built
      - run: ./gradlew assemble --no-daemon

      - uses: geckoprojects-org/org.gecko.bnd.sbom/.github/actions/bnd-update@<sha>
        with:
          scope: ${{ inputs.scope || 'micro' }}
          mode: each
          build-command: ./gradlew build -x test --no-daemon -q
          token: ${{ secrets.BND_UPDATE_TOKEN }}   # see "Token" below
```

### Vulnerability fixes

Export the SBOM, scan it, and pass the report. Use another branch, so that fixes and routine
updates are separate requests:

```yaml
      - run: ./gradlew assemble :app:sbom --no-daemon
      - run: trivy sbom --format json --output trivy.json app/generated/sbom/app.bndrun.cdx.json
      - uses: geckoprojects-org/org.gecko.bnd.sbom/.github/actions/bnd-update@<sha>
        with:
          trivy-report: trivy.json
          sbom: app/generated/sbom/app.bndrun.cdx.json
          branch: bnd-update/fixes
          title: 'bnd update: vulnerability fixes'
          labels: security
          build-command: ./gradlew build -x test --no-daemon -q
          token: ${{ secrets.BND_UPDATE_TOKEN }}
```

Run it daily, after the scan, or whenever the report job finds a fix.

### Inputs

| Input | Meaning | Default |
|---|---|---|
| `workspace` | the bnd workspace (directory that contains `cnf`), relative to the repository | `.` |
| `mode` | `each` (one by one, keep what passes) or `all` (all or nothing) | `each` |
| `scope` | default scope for the run (`micro`, `minor`, `major`); empty uses `-update-policy` | empty |
| `only` | only these libraries, comma separated `groupId:artifactId` patterns | all proposed |
| `trivy-report` | Trivy JSON report: apply its fixes instead of all updates | none |
| `sbom` | the CycloneDX SBOM the Trivy report was made from | none |
| `build-command` | build to run after resolving; a failing build reverts the update | none |
| `cli-jar` | a local CLI jar instead of downloading one | none |
| `cli-version` | version of the CLI to download (a `-SNAPSHOT` from the Central snapshot repository); the download is checked against the repository's checksum | `0.1.0-SNAPSHOT` |
| `create-pull-request` | open or update the pull request | `true` |
| `branch` | branch of the pull request, reused by later runs | `bnd-update/updates` |
| `title` | title of the pull request and the commit | `bnd update: dependency updates` |
| `labels` | labels, comma separated | `dependencies` |
| `token` | token for pushing and opening the pull request | `github.token` |
| `fail-on-reverted` | fail the step when an update had to be reverted, after the pull request for the others is opened | `false` |

| Output | Meaning |
|---|---|
| `exit-code` | exit code of `apply`: 0 nothing applied, 1 updates applied, 2 an update was reverted |
| `report` | path of the Markdown report |
| `pull-request-url` | URL of the opened or updated pull request |

### Token

With the default `GITHUB_TOKEN`, **no workflow runs on the pull request**: GitHub does not start
workflows for events caused by that token. The pull request then has no checks, and with branch
protection it cannot be merged.

Use one of:

- **a GitHub App** installed on the repository with *Contents* and *Pull requests* read/write,
  and `actions/create-github-app-token` to get a token in the job (recommended for
  organisations),
- **a fine-grained personal access token** limited to the repository, with *Contents* and *Pull
  requests* read/write, stored as a secret.

Also allow GitHub Actions to create pull requests: *Settings → Actions → General → Workflow
permissions → Allow GitHub Actions to create and approve pull requests*.

### Things to know

- Java 21 must be on the runner (`actions/setup-java`), plus whatever the build command needs.
- Build the workspace before the action (`./gradlew assemble`).
- Commits are signed off, so DCO checks pass.
- Pin the action to a commit SHA, like every action that gets a write token.
- To check the action itself in a pull request without opening one, set
  `create-pull-request: 'false'`. This repository does that in `.github/workflows/bnd-update.yml`.

## Jenkins and GitLab CI: the CI adapter

`ci/bnd-update.sh` does for any CI what the GitHub Action does on GitHub: fetch the CLI, run
`apply`, commit the verified updates (signed off) on a branch, push it, and open or update one
pull request (GitHub) or merge request (GitLab). It needs bash, git, curl and Java 21, no jq or
Python.

| Forge | What it needs |
|---|---|
| GitHub | `GITHUB_TOKEN`, `GITHUB_REPOSITORY` (`owner/repo`); `GITHUB_API_URL` and `GITHUB_SERVER` for GitHub Enterprise |
| GitLab | `GITLAB_TOKEN`, `CI_PROJECT_ID`, `CI_PROJECT_PATH`, `CI_API_V4_URL`, `CI_SERVER_URL` (set by GitLab CI itself) |
| neither | the updates are committed locally only |

### Configuration

All through the environment:

| Variable | Meaning | Default |
|---|---|---|
| `BND_UPDATE_WORKSPACE` | the bnd workspace directory | `.` |
| `MODE` | `each` or `all` | `each` |
| `SCOPE` | `micro`, `minor`, `major`; empty: `-update-policy` | empty |
| `ONLY` | `groupId:artifactId` patterns, comma separated | all proposed |
| `TRIVY_REPORT`, `SBOM` | apply the fixes for this Trivy report (and SBOM) | none |
| `BUILD_COMMAND` | build that verifies each update | none |
| `CLI_JAR` | a CLI jar; empty downloads `CLI_VERSION` | none |
| `CLI_VERSION` | version of `org.geckoprojects.bnd:org.gecko.bnd.update.cli` | `0.1.0-SNAPSHOT` |
| `BRANCH` | branch of the request | `bnd-update/updates` |
| `BASE` | target branch | GitLab: `CI_DEFAULT_BRANCH`; Jenkins: `CHANGE_TARGET` or `BRANCH_NAME`; else the current branch |
| `TITLE` | title of the request and the commit | `bnd update: dependency updates` |
| `LABELS` | labels, comma separated | `dependencies` |
| `GIT_NAME`, `GIT_EMAIL` | commit identity, also used for `Signed-off-by` | the git configuration |
| `DRY_RUN` | `true`: apply and commit locally, only show what would be pushed and requested | `false` |
| `FAIL_ON_REVERTED` | `true`: exit 2 when an update had to be reverted | `false` |

Exit codes: 0 done (or nothing to do), 2 an update was reverted and `FAIL_ON_REVERTED=true`, 1
failure. The report is also written to `bnd-update-report.md` for archiving.

### Pinning the script

The script runs with a write token. Download it from a fixed commit and check its SHA-256:

```
c=<commit>
curl -fsSL -o bnd-update.sh https://raw.githubusercontent.com/geckoprojects-org/org.gecko.bnd.sbom/$c/ci/bnd-update.sh
sha256sum bnd-update.sh     # this value goes into BND_UPDATE_SHA256
```

Or copy the script into your repository.

### Trying it

```
DRY_RUN=true GITHUB_TOKEN=... GITHUB_REPOSITORY=owner/repo BASE=main bash ci/bnd-update.sh
```

applies and commits the updates in the local checkout and shows whether it would open a new
request or update the existing one. Nothing is pushed.

## Jenkins

### Setup

| What | How |
|---|---|
| Java 21 | `tools { jdk 'OpenJDK21' }` (the name of the JDK installation in Jenkins) |
| bash, git, curl | on the agent |
| GitHub token | a *Secret text* credential with a fine-grained token (*Contents* and *Pull requests* read/write on the repository), passed as `GITHUB_TOKEN`, plus `GITHUB_REPOSITORY=owner/repo` |
| GitLab token | a project access token with `api` and `write_repository`, passed as `GITLAB_TOKEN`, plus `CI_PROJECT_ID`, `CI_PROJECT_PATH`, `CI_API_V4_URL`, `CI_SERVER_URL` (outside GitLab CI they are not set automatically) |
| commit identity | `GIT_NAME`, `GIT_EMAIL` |
| schedule | `triggers { cron(...) }`, guarded to the target branch |

A pull request opened with a personal or app token starts the repository's workflows, so it gets
its usual checks.

### The stage

Merge this stage into the repository's `Jenkinsfile`
(complete file: `ci/jenkins/Jenkinsfile.example`):

```groovy
pipeline {
    agent any
    tools { jdk 'OpenJDK21' }

    triggers {
        // weekly, only for the branch the updates go into
        cron(env.BRANCH_NAME == 'main' ? 'H 5 * * 2' : '')
    }

    options {
        disableConcurrentBuilds()
    }

    stages {
        // ... the usual build stages ...

        stage('bnd update') {
            when {
                allOf {
                    branch 'main'
                    anyOf {
                        triggeredBy 'TimerTrigger'
                        triggeredBy cause: 'UserIdCause'   // "Build now" by hand
                    }
                }
            }
            environment {
                BND_UPDATE_COMMIT = '<commit>'
                BND_UPDATE_SHA256 = '<sha256>'
            }
            steps {
                // a clean tree: apply rewrites files and commits them
                sh 'git reset --hard && git clean -fdx -e .gradle'
                sh './gradlew assemble --no-daemon'
                sh '''
                    curl -fsSL -o "$WORKSPACE@tmp/bnd-update.sh" \
                      "https://raw.githubusercontent.com/geckoprojects-org/org.gecko.bnd.sbom/$BND_UPDATE_COMMIT/ci/bnd-update.sh"
                    echo "$BND_UPDATE_SHA256  $WORKSPACE@tmp/bnd-update.sh" | sha256sum -c --strict -
                '''
                withCredentials([string(credentialsId: 'github-bnd-update-token', variable: 'GITHUB_TOKEN')]) {
                    sh '''
                        GITHUB_REPOSITORY=my-org/my-workspace \
                        BUILD_COMMAND="./gradlew build -x test --no-daemon" \
                        GIT_NAME="bnd update" GIT_EMAIL="bnd-update@example.org" \
                        bash "$WORKSPACE@tmp/bnd-update.sh"
                    '''
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'bnd-update-report.md', allowEmptyArchive: true
                }
            }
        }
    }
}
```

The script is stored next to the workspace (`$WORKSPACE@tmp`), so it is not committed with the
updates.

For a Jenkins that serves a GitLab project, pass `GITLAB_TOKEN` and the four `CI_*` variables
instead of the GitHub ones.

## GitLab CI

`ci/gitlab/bnd-update.gitlab-ci.yml` is a template with the hidden job `.bnd-update`. It runs the
CI adapter on a pipeline schedule.

### Setup

| What | How |
|---|---|
| token | a **project access token** (role Developer or higher) with the scopes `api` and `write_repository`, stored as the masked and protected CI/CD variable `GITLAB_TOKEN`. The job token (`CI_JOB_TOKEN`) can neither push nor open merge requests |
| schedule | *Build → Pipeline schedules*: target branch (e.g. `main`), weekly, variable `BND_UPDATE=true`. A manual pipeline (*Run pipeline*) with `BND_UPDATE=true` works as well |
| other jobs | the schedule runs the whole pipeline; give the other jobs `rules: - if: '$BND_UPDATE != "true"'` if they should not run then |
| runner | a Docker runner; the job uses `eclipse-temurin:21-jdk` and installs git when it is missing |
| commit identity | `GIT_NAME`/`GIT_EMAIL`, by default the user who owns the schedule or ran the pipeline |

The merge request is opened with the token of a project bot, so its pipeline runs as usual.

### `.gitlab-ci.yml`

```yaml
include:
  - remote: https://raw.githubusercontent.com/geckoprojects-org/org.gecko.bnd.sbom/<commit>/ci/gitlab/bnd-update.gitlab-ci.yml
    integrity: sha256-<base64>

stages: [build, update]

build:
  stage: build
  image: eclipse-temurin:21-jdk
  rules:
    - if: '$BND_UPDATE != "true"'      # not in the update pipeline
  script:
    - ./gradlew build --no-daemon
  artifacts:
    reports:
      cyclonedx:
        - "*/generated/sbom/*.cdx.json"

bnd-update:
  extends: .bnd-update
  stage: update
  variables:
    BND_UPDATE_COMMIT: <commit>
    BND_UPDATE_SHA256: <sha256>
    SCOPE: micro
```

Get the two checksums:

```
c=<commit>; base=https://raw.githubusercontent.com/geckoprojects-org/org.gecko.bnd.sbom/$c
curl -fsSL $base/ci/gitlab/bnd-update.gitlab-ci.yml | openssl dgst -sha256 -binary | base64   # integrity: sha256-...
curl -fsSL $base/ci/bnd-update.sh | sha256sum                                                  # BND_UPDATE_SHA256
```

`include:remote` with `integrity` needs GitLab 17.9 or later. On older instances, copy the
template into the repository and use `include:local`.

### Variables of the job

On top of the [adapter's configuration](#configuration):

| Variable | Meaning | Default |
|---|---|---|
| `PREPARE_COMMAND` | runs before bnd update; builds the workspace's bundles | `./gradlew assemble --no-daemon` |
| `BUILD_COMMAND` | build that verifies each update; empty: only the resolve check | `./gradlew build -x test --no-daemon` |
| `BND_UPDATE_COMMIT`, `BND_UPDATE_SHA256` | the pinned script | required |

### Fixes in GitLab

A second job for the fixes of a Trivy report, with its own branch:

```yaml
bnd-update-fixes:
  extends: .bnd-update
  stage: update
  variables:
    BND_UPDATE_COMMIT: <commit>
    BND_UPDATE_SHA256: <sha256>
    PREPARE_COMMAND: >-
      ./gradlew assemble :app:sbom --no-daemon &&
      trivy sbom --format json --output trivy.json app/generated/sbom/app.bndrun.cdx.json
    TRIVY_REPORT: trivy.json
    SBOM: app/generated/sbom/app.bndrun.cdx.json
    BRANCH: bnd-update/fixes
    TITLE: 'bnd update: vulnerability fixes'
```

The image needs Trivy for that (`eclipse-temurin` has none): install it in `before_script`, or
run the scan in an earlier job and pass `trivy.json` as artifact.

## Reviewing an update request

A request from bnd update contains:

- the changed lines of the `.mvn` indexes (one line per library),
- the new `-runbundles` of every bndrun whose resolution changed,
- the report as description: what was applied, what was reverted and why, what is outside the
  policy.

Before merging:

1. **Let the full pipeline run**: build, OSGi tests (`testOSGi`), CodeQL, SBOM and Trivy.
2. **Read the reverted updates.** "Reverted updates that fail on each other" lists groups that
   only work together, with the command to retry them together
   (`apply --mode all --only ...`).
3. **Look at "Outside the version policy".** A fix that needs a minor or major step is a
   decision: widen the policy for that library in `cnf/build.bnd`, or wait.
4. **Merge.** The next run starts from there; an open request is updated, not duplicated.

## Troubleshooting

**The pull request has no checks.**
It was opened with the default `GITHUB_TOKEN`. Use an app or fine-grained token, see
[Token](#token).

**"the workspace does not resolve even without updates", nothing applied.**
The workspace's own bundles were not built before `apply`, or a bndrun is already broken on the
base branch. Build first (`./gradlew assemble`), and check with `bnd-update resolve`.

**Every update is reverted with the same reason.**
Usually the build command fails for another reason (missing tool on the runner, network). Run the
build command by hand on the base branch.

**`-runfw: ... pins a version the update removes`.**
A bndrun pins its framework to an exact version (`-runfw: org.apache.felix.framework;version='[7.0.5,7.0.5]'`)
and the update changed that version in the index. Pin a range instead, or update the bndrun by
hand.

**HTTP 429 from Maven Central.**
Central rate-limits runners that download a lot. Cache `~/.m2/repository` between runs.

**GitLab: `GITLAB_TOKEN is not set`, or the push is rejected.**
The variable must be a project access token with `api` and `write_repository`. A protected
variable is only available on protected branches: run the schedule on a protected branch.
