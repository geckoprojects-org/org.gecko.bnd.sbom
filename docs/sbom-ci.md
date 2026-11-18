# SBOMs in CI: export, scan, publish

An SBOM is useful when it is produced on every build and checked continuously: new
vulnerabilities are published every day for components that did not change. This page shows
complete CI setups for GitHub Actions, GitLab CI and Jenkins:

1. **export** the SBOM of each application bndrun,
2. **scan** it with Trivy,
3. **propose fixes** for what Trivy finds, with bnd update,
4. **publish** the SBOM and the results.

How to export with [Gradle](sbom-gradle.md) or [Maven](sbom-maven.md) is described on their
pages; the commands below assume the Gradle workspace of
[examples/gradle-workspace](../examples/gradle-workspace/README.md) with its `sbom` task.

## Recommendations

| Recommendation | Why |
|---|---|
| Export on every build, from the same commit that is shipped | the SBOM must describe what is delivered, not what was there last week |
| Scan on every build **and** on a schedule (daily) | vulnerabilities are published for unchanged components |
| Scan the SBOM of the bndrun, not the `pom.xml` or the source tree | only the bndrun says what runs; see [Maven scopes](maven-scopes.md) |
| Report findings, do not fail every build on them | a new CVE in an unchanged dependency should not block unrelated work; fail on what needs a decision instead (exit code 2 of bnd update) |
| Keep the SBOM as a build artifact, and attach it to releases | customers and authorities ask for the SBOM of a specific release |
| Pin CI actions and tools by commit or checksum | the pipeline handles credentials and produces what you ship |
| `level=medium` with `validate=bsi-tr-03183-2` | complete SBOMs, and gaps show up as warnings in the build |

## GitHub Actions

A workflow that exports the SBOM, scans it, writes the results into the run's summary and the
repository's Security tab, and lists the fix versions. It is the workflow this repository uses
for itself (`.github/workflows/sbom.yml`), shortened.

```yaml
name: SBOM and Trivy

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '17 4 * * *'      # daily: new vulnerabilities for unchanged components
  workflow_dispatch:

permissions:
  contents: read

jobs:
  sbom:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # upload to code scanning
    steps:
      - uses: actions/checkout@<sha>
      - uses: actions/setup-java@<sha>
        with:
          distribution: temurin
          java-version: '21'
      - uses: gradle/actions/setup-gradle@<sha>

      - name: SBOM
        run: ./gradlew sbom --no-daemon

      - name: Upload SBOM
        uses: actions/upload-artifact@<sha>
        with:
          name: sbom
          path: '**/generated/sbom/*.json'

      # findings as SARIF for the Security tab; reporting only (exit-code 0)
      - name: Trivy (SARIF)
        uses: aquasecurity/trivy-action@<sha>
        with:
          scan-type: sbom
          scan-ref: example.app/generated/sbom/app.bndrun.cdx.json
          format: sarif
          output: trivy-results.sarif
          exit-code: '0'

      # the same findings as JSON, for bnd update
      - name: Trivy (JSON)
        uses: aquasecurity/trivy-action@<sha>
        with:
          scan-type: sbom
          scan-ref: example.app/generated/sbom/app.bndrun.cdx.json
          format: json
          output: trivy-results.json
          exit-code: '0'
          skip-setup-trivy: true

      # the fix version within the version policy for every finding
      - name: Fixes
        run: ./gradlew bndVulnerabilities -PtrivyReport=trivy-results.json --no-daemon

      - name: Summary
        if: always()
        run: cat build/bnd-update/vulnerabilities.md >> "$GITHUB_STEP_SUMMARY"

      # not for pull requests: their token cannot write security events
      - name: Upload to code scanning
        if: github.event_name != 'pull_request'
        uses: github/codeql-action/upload-sarif@<sha>
        with:
          sarif_file: trivy-results.sarif
          category: trivy-sbom
```

`bndVulnerabilities` comes from the [bnd update Gradle plugin](bnd-update-gradle.md);
`-PtrivyReport` works because the example's `build.gradle` sets `bndUpdate.trivyReport` from that
property ([how](bnd-update-gradle.md#configuration-from-the-command-line)). Without the plugin,
call the CLI directly, as this repository does:

```yaml
      - name: Fixes
        run: |
          java -jar org.gecko.bnd.update.cli.jar vulnerabilities \
            --trivy trivy-results.json \
            --sbom example.app/generated/sbom/app.bndrun.cdx.json \
            --format markdown --output fixes.md || true
          cat fixes.md >> "$GITHUB_STEP_SUMMARY"
```

The summary of every run then shows, even when there is nothing to fix:

```
## Vulnerabilities — app.bndrun

| Library | Installed | Vulnerabilities | Fix | Where |
|---|---|---|---|---|
| `org.slf4j:slf4j-api` | 2.0.17 | 1 (HIGH) | **2.0.18** (minor) | runbundle, Central |
| `org.apache.felix:org.apache.felix.framework` | 7.0.5 | 1 (MEDIUM) | needs a major update (allowed: micro) | runfw, Central |
```

To apply the fixes and open a pull request automatically, see
[bnd update in CI](bnd-update-ci.md#github-actions).

**Caching.** bnd downloads its repositories into `~/.m2/repository`. Cache it with
`actions/cache`, keyed on the `.mvn` indexes, so that not every run fetches everything from
Maven Central again; Central rate-limits CI runners that do (HTTP 429). This repository's
workflows show how.

## GitLab CI

GitLab reads CycloneDX SBOMs as a report: the components appear in the project's dependency
list and, on tiers with dependency scanning, with their known vulnerabilities.

```yaml
stages: [build, scan]

build:
  stage: build
  image: eclipse-temurin:21-jdk
  script:
    - ./gradlew build sbom --no-daemon
  artifacts:
    paths:
      - "*/generated/sbom/*.json"
    reports:
      cyclonedx:
        - "*/generated/sbom/*.cdx.json"

trivy:
  stage: scan
  image:
    name: aquasec/trivy:<version>
    entrypoint: [""]
  needs: [build]
  script:
    - trivy sbom --format json --output trivy.json example.app/generated/sbom/app.bndrun.cdx.json
    - trivy sbom --format table example.app/generated/sbom/app.bndrun.cdx.json
  artifacts:
    paths: [trivy.json]
    when: always

fixes:
  stage: scan
  image: eclipse-temurin:21-jdk
  needs: [build, trivy]
  script:
    - ./gradlew bndVulnerabilities -PtrivyReport=trivy.json --no-daemon
  artifacts:
    paths: [build/bnd-update/]
    when: always
  allow_failure:
    exit_codes: [1]
```

Add a pipeline schedule (*Build → Pipeline schedules*, daily) so the scan runs on unchanged code
as well. Which GitLab tiers and CycloneDX versions show what has not been checked on a GitLab
instance yet; the exporter writes CycloneDX 1.6 by default.

To apply updates and open merge requests from GitLab, see
[bnd update in CI](bnd-update-ci.md#gitlab-ci).

## Jenkins

The pipeline of [examples/gradle-workspace/Jenkinsfile](../examples/gradle-workspace/Jenkinsfile):

```groovy
pipeline {
    agent any
    tools { jdk 'OpenJDK21' }

    stages {
        stage('Build') {
            steps { sh './gradlew build --no-daemon' }
        }
        stage('SBOM') {
            steps { sh './gradlew sbom --no-daemon' }
        }
        stage('Trivy') {
            steps {
                sh 'trivy sbom --format json --output trivy.json example.app/generated/sbom/app.bndrun.cdx.json'
                // without Trivy on the agent:
                // sh 'docker run --rm -v "$PWD:/work" -w /work aquasec/trivy:<version> sbom --format json --output trivy.json example.app/generated/sbom/app.bndrun.cdx.json'
            }
        }
        stage('Fixes') {
            steps {
                // a vulnerability without a fix within the policy, or a bndrun that does not
                // resolve, makes the build unstable, not failed
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh './gradlew bndVulnerabilities bndResolveCheck -PfailOnFindings=true --no-daemon'
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts allowEmptyArchive: true,
                artifacts: 'example.app/generated/sbom/*.json,trivy.json,build/bnd-update/*'
        }
    }
}
```

For a daily scan, add `triggers { cron('H 4 * * *') }`. The weekly pull request with the
updates is described in [bnd update in CI](bnd-update-ci.md#jenkins).

For Maven projects the stages are `mvn package` (SBOM), Trivy, and `mvn verify
-Dbnd-update.failOn=unfixable` (fixes): see
[examples/maven-sbom/Jenkinsfile](../examples/maven-sbom/Jenkinsfile).

## Dependency-Track

[Dependency-Track](https://dependencytrack.org/) keeps the SBOM of every version and watches it
for new vulnerabilities. Upload the CycloneDX SBOM with its REST API at the end of the build:

```
curl -fsS -X POST "$DT_URL/api/v1/bom" \
  -H "X-Api-Key: $DT_API_KEY" \
  -F "autoCreate=true" \
  -F "projectName=my-application" \
  -F "projectVersion=$VERSION" \
  -F "bom=@example.app/generated/sbom/app.bndrun.cdx.json"
```

Use an API key of a team that may only upload BOMs (permission `BOM_UPLOAD`, plus
`PROJECT_CREATION_UPLOAD` for `autoCreate`).

## Validating the SBOM

To make sure every SBOM a build produces is valid, check it against the official JSON schema of
its format. This repository does that in CI with `.github/scripts/validate-sbom.py` and the
schemas pinned by checksum in `.github/schemas.sha256`; both can be copied.
