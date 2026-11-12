# bnd update: finding updates and fixes for bnd workspaces

`org.gecko.bnd.update` answers three questions for a bnd workspace and does one thing:

1. **Which of our libraries have newer versions?** — independent of any vulnerability report.
2. **Which of our vulnerable libraries can be fixed, and with which version?** — for a Trivy
   report, using what the workspace's repositories actually offer.
3. **Does every bndrun still resolve — and to what?** — the safety check after any update.
4. **Apply** updates — all, a selection, or the fixes of a Trivy report — and prove the result:
   every bndrun resolves, the new `-runbundles` are written, the build passes; what fails is
   reverted.

1–3 only read. Only `apply` changes files.

The same logic is available as a Java library, as a command line, as Maven and Gradle plugins,
as a GitHub Action and as a CI adapter for Jenkins and GitLab CI. Everything in this document applies to all of them.

- [Why not Dependabot](#why-not-dependabot)
- [How it works](#how-it-works)
- [The version policy](#the-version-policy)
- [Choosing the fix version](#choosing-the-fix-version)
- [Command line](#command-line)
- [Using it as a library](#using-it-as-a-library)
- [In CI](#in-ci)
- [CI adapter (Jenkins, GitLab CI)](#ci-adapter-jenkins-gitlab-ci)
- [Maven](#maven)
- [GitHub Action](#github-action)
- [After an update: resolve every bndrun](#after-an-update-resolve-every-bndrun)
- [Limits](#limits)
- [Roadmap](#roadmap)

## Why not Dependabot

Dependabot and Renovate do not understand bnd workspaces:

- the versions live in the **`.mvn` index files** of `MavenBndRepository` (`cnf/*.mvn`), not in a
  `pom.xml` or `build.gradle`;
- an update of an index line alone **breaks the bndruns**: their `-runbundles` pin exact
  version ranges (`version='[2.19.2,2.19.3)'`) and must be resolved again;
- a library **embedded** in a workspace bundle (inlined from the `-buildpath`) is updated in that
  project's build path, not in an index.

bnd itself knows the newer versions — the Bndtools repository view shows them ("Update
Revisions") and `bnd mbr check` lists them. This tool builds on exactly that mechanism, adds a
version policy, and matches the result against vulnerability reports.

## How it works

### Function 1: updates

For every library in the workspace's Maven repository indexes (`.mvn` files of every
`MavenBndRepository`):

1. bnd reads the library's `maven-metadata.xml` from the repositories whose index holds it,
   with the workspace's connection settings (credentials, proxies, mirrors);
2. snapshots and pre-releases (`-SNAPSHOT`, `-rc1`, `-beta2`, `-M3`, ...) are dropped;
3. the **proposal** is the *highest* remaining version that the [version policy](#the-version-policy)
   allows; the *latest* version is reported as well, with the scope it would need.

Libraries without a newer version are not listed.

### Function 3: resolve

Resolves every bndrun of the workspace (the `*.bndrun` files at the top level of each project)
with bnd's resolver — the same resolver the Gradle `resolve` tasks and Bndtools use — and
compares the result with the `-runbundles` in the file. Nothing is written.

| Status | Meaning |
|---|---|
| `UNCHANGED` | resolves to exactly the `-runbundles` in the file |
| `CHANGED` | resolves, but to other `-runbundles`: the report lists the bundles added and removed |
| `FAILED` | does not resolve: the report lists the **unresolved requirements** — which bundle requires which package, bundle or capability in which version range |
| `ERROR` | could not be evaluated (broken file, workspace error) |

`CHANGED` is not an error, but it means the checked-in bndrun does not describe what the
workspace resolves today: the indexes offer other versions (`guava 33.5.0 → 33.6.0`), or a
released bundle now wins over a workspace project with a lower version. After an intended
update this is expected and the new `-runbundles` belong in the commit; without one it is drift
that should be looked at.

For a `FAILED` bndrun the unresolved requirements are the reason, e.g.
`aQute.libg 7.4.0 -> osgi.wiring.package: org.slf4j; version=[2.0.0,3.0.0)`: nothing in the
repositories exports `org.slf4j` in that range. After an update this is how a too narrow import
range shows up. bnd's resolver reports it exactly, so no separate pre-check of import ranges is
needed.

### Function 4: apply

`apply` changes the workspace. For each update it replaces the version in the `.mvn` index —
**in place**, only the version field of that line, so the diff is one line per library; lines
whose version is a macro (`biz.aQute.bnd:biz.aQute.bndlib:${bndversion}`) are left alone, the
macro is the deliberate source of that version. Then it proves the result:

1. every bndrun of the workspace is resolved again ([function 3](#function-3-resolve));
2. if all resolve, the new `-runbundles` are written into the bndruns that change;
3. if a build command is given, the workspace is built;
4. if a bndrun does not resolve or the build fails, the update is **reverted**: the index and
   every bndrun are restored byte for byte.

Two modes:

| Mode | How | Use when |
|---|---|---|
| `all` (default) | all updates together, checked once; if the check fails, all are reverted | the updates belong together, one PR/MR for all |
| `each` | one after the other, each on top of the ones kept so far; a failing one is reverted and the next one tried | you want to know which update breaks what, or keep everything that works |

What `apply` updates and what not:

| Library | Changed by `apply` | Status in the report |
|---|---|---|
| in a text index (`.mvn`) with a version within the policy | yes | `APPLIED`, or `REVERTED` with the reason |
| version is a macro in the index | no | `SKIPPED_MACRO` |
| no version within the policy | no | `NOT_PROPOSED` (listed under "Outside the version policy") |
| any, when the workspace does not resolve before the first update | no | `NOT_APPLIED` |
| embedded in a workspace bundle (`-buildpath`), or in a pom index | no | `NOT_IN_INDEX` — update the `-buildpath` of the bundle by hand |

Run `apply` on a branch or a working copy, never on a checkout with uncommitted work: it rewrites
files. The Git diff afterwards is the update.

**Build the workspace first.** A bndrun that runs bundles of the workspace itself can only resolve
when they are built (`./gradlew assemble`). `apply` therefore resolves every bndrun *before* the
first update: if that fails, it applies nothing and reports the failing bndruns
("the workspace does not resolve even without updates", status `NOT_APPLIED`, exit 2) — instead
of blaming updates for a failure they did not cause. `resolve` has the same requirement.

### Function 2: vulnerabilities

Input is a Trivy JSON report (`trivy sbom --format json <sbom>`), optionally the SBOM it was made
from. For every Maven library Trivy reports as vulnerable:

1. the available versions come from the workspace's repositories (as above) — or, with
   `--against-updates`, only from the result of function 1;
2. the **proposal** is the *smallest* version that fixes *all* of the library's vulnerabilities
   and that the policy allows ([how a fix is recognized](#choosing-the-fix-version));
3. if there is none, the report says which scope a fix would need — or that no available
   version fixes everything;
4. with `--sbom`, each library gets its location from the SBOM: a run bundle, the framework,
   a `-runpath` jar, or **embedded in** a workspace bundle (and from which `-buildpath` entry) —
   which tells what has to change.

Each library ends up in one of three states:

| Status | Meaning | What to do |
|---|---|---|
| `UPDATE` | a version within the policy fixes everything | update to the proposed version |
| `OUTSIDE_POLICY` | a fix exists, but only in a larger scope than allowed | decide: widen the policy for this library, or wait for a fix in the current line |
| `NO_FIX` | no available version fixes all vulnerabilities | check the advisories; mitigate, replace the library, or accept the risk explicitly |

## The version policy

How far an update may move from the installed version:

| Scope | Allows | Example from 2.19.2 |
|---|---|---|
| `micro` | same major and minor version | 2.19.3, 2.19.10 |
| `minor` | same major version | 2.20.1, 2.21.7 |
| `major` | any higher version | 3.0.0 |

**The default is `micro`.** Bug-fix releases of the same line are the ones most likely to be
compatible — with the APIs the bundles use and with the import version ranges in their
manifests. Larger steps are allowed only where configured; **major updates are never proposed
unless configured explicitly**.

The policy is set in the workspace (`cnf/build.bnd` or a file in `cnf/ext/`):

```
-update-policy: \
	default;scope=micro,\
	com.fasterxml.jackson.core:*;scope=minor,\
	org.bouncycastle:bcprov-jdk18on;scope=minor
```

- Entries are `groupId:artifactId` patterns; `*` matches any part of a group or artifact id.
- The **first** matching entry wins; `default` applies when none matches (and is `micro` when
  absent).
- On the command line, `--scope` overrides `default` for one run; the per-library entries stay.

Why per library: not every library follows semantic versioning. Bouncy Castle counts releases in
the minor digit (1.82 → 1.85 is a bug-fix step there); Jackson maintains several minor lines in
parallel and fixes only some of them. The policy is where that knowledge is written down.

**Variants are kept.** Some libraries publish variants of one release with a suffix, like guava
`33.5.0-jre` and `33.5.0-android`. An update never switches the variant: `-jre` only moves to
`-jre`, a version without suffix only to versions without one.

## Choosing the fix version

Trivy reports for each vulnerability one fixed version per maintained line, e.g.
`2.18.11, 2.21.7, 2.22.3`. Read as: affected are versions below 2.18.11, and in the 2.21 line
those below 2.21.7, and in the 2.22 line those below 2.22.3. Lines in between (2.19, 2.20) have
no fix.

A candidate version is taken as fixed when the highest fixed version **not above it** is in the
candidate's own major.minor line, or is the highest fixed version of all:

| Candidate | Fixed? | Why |
|---|---|---|
| 2.18.11 | yes | fixed version of its own line |
| 2.19.5 | no | highest fixed version below is 2.18.11 — another line, and not the highest |
| 2.21.7 | yes | fixed version of its own line |
| 2.23.0 | yes | above the highest fixed version 2.22.3 |

The proposal is the **smallest** candidate within the policy that fixes **all** vulnerabilities
of the library — the smallest step that closes everything that is known.

Example from a real workspace (org.gecko.libraries, `io.minio`): jackson-databind 2.19.2 has 12
vulnerabilities, none fixed in the 2.19 line. With the default policy it is `OUTSIDE_POLICY`
("needs a minor update"); with `minor` allowed for Jackson the proposal is 2.21.7.

Without range data from the advisory this is the closest reading of the fixed-version list. When
in doubt, check the advisory itself.

## Command line

`org.gecko.bnd.update.cli` is a self-contained executable jar (bnd included). It runs in a bnd
workspace without a bnd installation.

```
java -jar org.gecko.bnd.update.cli.jar <command> [options]
```

### `updates`

```
updates [--workspace DIR] [--scope micro|minor|major] [--format text|json|markdown] [--output FILE]
```

Lists the libraries of the `.mvn` indexes with newer versions; the proposal per library is the
highest version within the policy.

### `vulnerabilities`

```
vulnerabilities --trivy FILE [--sbom FILE] [--against-updates]
                [--workspace DIR] [--scope micro|minor|major] [--format text|json|markdown] [--output FILE]
```

For each vulnerable library in the Trivy report: the smallest available version within the
policy that fixes all its vulnerabilities.

### `resolve`

```
resolve [--workspace DIR] [--format text|json|markdown] [--output FILE]
```

Resolves every bndrun of the workspace without writing, and reports per bndrun whether it
resolves unchanged, changed (with the bundles added and removed) or not at all (with the
unresolved requirements). Run it after every update; see
[After an update](#after-an-update-resolve-every-bndrun).

### `apply`

```
apply [--only G:A,...] [--from-vulnerabilities TRIVY [--sbom SBOM]] [--mode all|each]
      [--build-command CMD] [--workspace DIR] [--scope micro|minor|major] [--format text|json|markdown] [--output FILE]
```

**Changes the workspace.** Without `--only` and `--from-vulnerabilities` it applies every update
`updates` proposes. Examples:

```
# all micro updates, together, checked with a Gradle build
java -jar org.gecko.bnd.update.cli.jar apply --build-command "./gradlew build -x test"

# only Jackson, minor allowed for this run
java -jar org.gecko.bnd.update.cli.jar apply --only "com.fasterxml.jackson.core:*" --scope minor

# the fixes of a Trivy report, one by one, keeping what works
java -jar org.gecko.bnd.update.cli.jar apply --from-vulnerabilities trivy.json --sbom app.cdx.json --mode each
```

Then review `git diff` — the changed index lines and `-runbundles` — run the OSGi tests and commit.

### Options

| Option | Meaning | Default |
|---|---|---|
| `--workspace DIR` | the bnd workspace (the directory that contains `cnf`) | current directory |
| `--scope S` | default scope of the policy for this run; per-library entries of `-update-policy` stay | from `-update-policy`, else `micro` |
| `--format F` | `text` for a terminal, `json` for tools, `markdown` for a CI summary, PR/MR or issue | `text` |
| `--output FILE` | write the report to a file instead of standard output | standard output |
| `--trivy FILE` | Trivy JSON report (`trivy sbom --format json`) | required for `vulnerabilities` |
| `--sbom FILE` | the CycloneDX SBOM the Trivy report was made from; adds where each library sits | none |
| `--against-updates` | consider only the versions function 1 finds, instead of everything the repositories offer | off |
| `--only G:A,...` | `apply`: only these libraries; `groupId:artifactId` patterns, `*` matches any part | all proposed |
| `--from-vulnerabilities FILE` | `apply`: apply the fixes `vulnerabilities` proposes for this Trivy report (with `--sbom` for locations) | — |
| `--mode all\|each` | `apply`: together (all or nothing) or one by one (keep what passes) | `all` |
| `--build-command CMD` | `apply`: build to run after resolving, in the workspace directory (`sh -c`, on Windows `cmd /c`); a failing build reverts the update | none |

Workspace errors and warnings go to standard error; the report goes to standard output or the
output file. bnd's own logging is set to warnings (override with
`-Dorg.slf4j.simpleLogger.defaultLogLevel=info`).

### Exit codes

| Code | `updates` | `vulnerabilities` | `resolve` | `apply` |
|---|---|---|---|---|
| 0 | nothing to update | nothing vulnerable | every bndrun resolves to its current `-runbundles` | nothing applied (nothing to do) |
| 1 | updates within the policy | every vulnerable library has a fix within the policy | every bndrun resolves, some to other `-runbundles` | updates applied and verified — the working tree has changes to commit |
| 2 | — | at least one library has no fix within the policy (`OUTSIDE_POLICY` or `NO_FIX`) | at least one bndrun does not resolve | at least one update was reverted, or the workspace does not resolve without updates (see the report) |
| 64 | usage error | usage error | usage error | usage error |
| 70 | internal error | internal error | internal error | internal error |

A CI job can therefore fail on 2 (something needs a decision), report on 1 and pass on 0.

## Using it as a library

The core is a plain Java library on top of bnd (`biz.aQute.bndlib`, `biz.aQute.repository`);
it needs no Gradle, Maven or CI. Maven coordinates: `org.geckoprojects.bnd:org.gecko.bnd.update`.

```java
try (Workspace workspace = new Workspace(new File("/path/to/workspace"))) {

	// function 1: newer versions within the workspace's -update-policy
	List<Update> updates = UpdateFinder.forWorkspace(workspace).find();

	// function 2: fixes for a Trivy report, with locations from the SBOM
	VulnerabilityCheck check = VulnerabilityCheck.forWorkspace(workspace)
		.withPolicy(VersionPolicy.from(workspace).withDefault(Scope.MINOR));
	CheckReport report;
	try (InputStream sbom = Files.newInputStream(sbomFile);
		InputStream trivy = Files.newInputStream(trivyFile)) {
		report = check.check(Sbom.read(sbom), TrivyReport.read(trivy));
	}
	for (Proposal p : report.withStatus(Proposal.Status.UPDATE)) {
		System.out.println(p.library() + " -> " + p.proposed());
	}

	// function 4: apply the proposed updates one by one, with a Gradle build
	ApplyReport applied = new UpdateApplier(workspace.getBase(), BuildStep.command("./gradlew build -x test"))
		.apply(updates, UpdateApplier.Mode.EACH);

	// function 3: does every bndrun still resolve?
	ResolveReport resolved = new ResolveCheck(workspace).resolveAll();
	if (!resolved.allResolve()) {
		resolved.withStatus(BndrunResult.Status.FAILED)
			.forEach(r -> System.out.println(r.bndrun() + ": " + r.unresolved()));
	}

	// renderings
	String markdown = Reports.markdown(report);
	String json = Reports.json(updates);
}
```

| Type | Role |
|---|---|
| `UpdateFinder` | function 1 |
| `VulnerabilityCheck` | function 2; `againstUpdates(...)` uses a given list of updates as the versions on offer |
| `VersionPolicy`, `Scope` | the policy and its scopes |
| `FixSelector` | the fix-version rules, usable on their own |
| `VersionSource` | where available versions come from; `MavenRepositoryVersions` reads the workspace's repositories, tests and other tools can supply their own |
| `TrivyReport`, `Sbom` | the inputs |
| `Update`, `Proposal`, `CheckReport`, `Location` | the results |
| `ResolveCheck` | function 3: resolves all (or given) bndruns without writing |
| `UpdateApplier`, `BuildStep` | function 4: applies updates (`ALL`/`EACH`), verifies, reverts; the build is any command |
| `ApplyReport`, `AppliedUpdate` | its results per update |
| `IndexEditor` | changes one library's version in a `.mvn` index in place |
| `ResolveReport`, `BndrunResult` | its results: status, added/removed bundles, unresolved requirements |
| `Reports` | JSON and Markdown renderings |

## In CI

The command line is the same everywhere; only how it is called differs. A typical job: export the
SBOMs, scan them with Trivy, run the check, publish the report.

**Jenkins** — the report only, the CLI directly:

```groovy
stage('Vulnerability fixes') {
    steps {
        sh './gradlew :app:sbom'
        sh 'trivy sbom --format json --output trivy.json app/generated/sbom/app.bndrun.cdx.json'
        script {
            def rc = sh(returnStatus: true, script:
                'java -jar org.gecko.bnd.update.cli.jar vulnerabilities --trivy trivy.json ' +
                '--sbom app/generated/sbom/app.bndrun.cdx.json --format markdown --output fixes.md')
            archiveArtifacts artifacts: 'fixes.md'
            if (rc == 2) { unstable('vulnerabilities without a fix within the version policy') }
        }
    }
}
```

To apply the updates and open a pull/merge request from Jenkins, use the
[CI adapter](#ci-adapter-jenkins-gitlab-ci).

**GitLab CI**

```yaml
vulnerability-fixes:
  script:
    - ./gradlew :app:sbom
    - trivy sbom --format json --output trivy.json app/generated/sbom/app.bndrun.cdx.json
    - java -jar org.gecko.bnd.update.cli.jar vulnerabilities --trivy trivy.json
        --sbom app/generated/sbom/app.bndrun.cdx.json --format markdown --output fixes.md
  artifacts:
    paths: [fixes.md]
    when: always
  allow_failure:
    exit_codes: [1]
```

**GitHub Actions** — the CLI directly:

```yaml
- run: |
    java -jar org.gecko.bnd.update.cli.jar vulnerabilities --trivy trivy.json \
      --sbom app/generated/sbom/app.bndrun.cdx.json --format markdown --output fixes.md
    cat fixes.md >> "$GITHUB_STEP_SUMMARY"
```

or the [GitHub Action](#github-action), which also opens the pull request. Ready-made GitLab CI
and Jenkins adapters that open merge requests are planned (#38); until then the CLI in a job, as
above, plus the forge's API.

## CI adapter (Jenkins, GitLab CI)

`ci/bnd-update.sh` does for any CI what the [GitHub Action](#github-action) does on GitHub: fetch
the CLI, run `apply`, commit the verified updates (signed off) on a branch, push it and open or
update one pull request (GitHub, via `GITHUB_TOKEN` + `GITHUB_REPOSITORY`) or merge request
(GitLab, via `GITLAB_TOKEN` + the `CI_*` variables). Without a token it commits locally only;
with `DRY_RUN=true` it shows what it would push and request. It needs bash, git, curl and Java 21,
no jq or Python.

For Jenkins: [ci/jenkins/README.md](../ci/jenkins/README.md) and the pipeline
`ci/jenkins/Jenkinsfile.example` (weekly cron on the main branch, credentials, pinned script).

For GitLab CI: [ci/gitlab/README.md](../ci/gitlab/README.md) and the template
`ci/gitlab/bnd-update.gitlab-ci.yml`. It has a hidden job `.bnd-update` for a pipeline schedule
with `BND_UPDATE=true`, needs a project access token as `GITLAB_TOKEN`, and is included pinned with
`integrity`. The example `ci/gitlab/gitlab-ci.example.yml` also hands the SBOMs to GitLab as a
`cyclonedx` report.

## Maven

For projects built with the bnd Maven plugins, see the runnable example
[examples/maven-sbom](../examples/maven-sbom/README.md).

- **SBOM:** `bnd-export-maven-plugin` with `<exporter>bnd.sbom</exporter>` and
  `org.geckoprojects.bnd:org.gecko.bnd.sbom` as plugin dependency; in the bndrun
  `-plugin.sbom: org.gecko.bnd.sbom.SbomExporter`. No plugin of our own is needed.
- **Vulnerability fixes:** `org.geckoprojects.bnd:bnd-update-maven-plugin`, goal
  `vulnerabilities` (phase `verify`): the [vulnerabilities function](#function-2-vulnerabilities)
  with the versions of the project's Maven repositories, resolved by Maven itself (mirrors,
  proxies, credentials of `settings.xml`). Parameters `trivyReport`, `sbom`, `scope`, `policy`
  (`-update-policy` syntax), `format`, `failOn` (`none`, `unfixable`, `vulnerable`), `skip`; report
  in `target/bnd-update/`.
- **Updates and re-resolution:** in a Maven project the versions live in the `pom.xml`, which
  Dependabot updates natively; `bnd-resolver-maven-plugin` re-resolves the bndruns afterwards.
  The plugin therefore has no `apply` goal.

The plugin is built with Maven in `maven-plugin/` (outside the bnd workspace) against the
`org.gecko.bnd.update` library.

## Gradle

For bnd workspaces built with Gradle, the plugin `org.geckoprojects.bnd.update` (built in
`gradle-plugin/`, outside the bnd workspace) adds the four functions as tasks of the root project:

| Task | Function | Changes files |
|---|---|---|
| `bndUpdates` | [updates](#function-1-updates) | no |
| `bndVulnerabilities` | [vulnerabilities](#function-2-vulnerabilities), needs `trivyReport` | no |
| `bndResolveCheck` | [resolve](#function-3-resolve), depends on every project's `jar` | no |
| `bndApply` | [apply](#function-4-apply), depends on every project's `jar` | **yes** |

```groovy
// settings.gradle: pluginManagement { repositories { gradlePluginPortal(); mavenCentral() } }
plugins {
    id 'org.geckoprojects.bnd.update' version '0.1.0-SNAPSHOT'
}

bndUpdate {
    scope = 'micro'                          // unset: the workspace's -update-policy
    mode = 'each'                            // bndApply: each or all
    only = ['com.fasterxml.jackson.*:*']     // bndApply: only these libraries
    buildCommand = './gradlew build -x test' // bndApply: verify each update
    trivyReport = file('trivy.json')         // bndVulnerabilities; bndApply applies its fixes
    sbom = file('generated/sbom/app/app.cdx.json')
    format = 'markdown'                      // text, json, markdown
    failOnFindings = false                   // fail on exit 2 (needs a decision)
    // cliJar.from('path/to/org.gecko.bnd.update.cli.jar'), or cliVersion = '...'
}
```

Reports go to `build/bnd-update/<command>.<md|json|txt>` (`outputDirectory`). Exit 0 and 1 are
results; 2 fails the task only with `failOnFindings`; anything else always fails it. The tasks
are never up to date: the answer depends on the repositories, not only on the inputs.

The tasks run the [CLI](#command-line) jar (`org.geckoprojects.bnd:org.gecko.bnd.update.cli`,
configuration `bndUpdateCli`) in **its own JVM**: the bnd Gradle plugin already brings a bndlib
into the build, and a second one of another version in the same classloader would conflict.

## GitHub Action

`.github/actions/bnd-update` runs `apply` and turns the result into **one pull request**: it
fetches the CLI (or uses a given jar), applies the updates, writes the report into the job
summary and the pull request description, and opens the pull request — or updates it, when the
branch already has one, so that repeated runs do not pile up pull requests.

```yaml
jobs:
  update:
    runs-on: ubuntu-latest
    permissions:
      contents: write        # push the update branch
      pull-requests: write   # open the pull request
    steps:
      - uses: actions/checkout@<sha>
      - uses: actions/setup-java@<sha>
        with: { distribution: temurin, java-version: '21' }
      - run: ./gradlew assemble          # the workspace's bundles, needed to resolve
      - uses: geckoprojects-org/org.gecko.bnd.sbom/.github/actions/bnd-update@<sha>
        with:
          mode: each
          build-command: ./gradlew build -x test --no-daemon
```

For vulnerability fixes, export the SBOM and scan it first, then pass the report:

```yaml
      - run: ./gradlew :app:export.app   # or the SBOM task of the workspace
      - run: trivy sbom --format json --output trivy.json app/generated/app.bndrun.cdx.json
      - uses: geckoprojects-org/org.gecko.bnd.sbom/.github/actions/bnd-update@<sha>
        with:
          trivy-report: trivy.json
          sbom: app/generated/app.bndrun.cdx.json
          branch: bnd-update/fixes
          title: 'bnd update: vulnerability fixes'
```

| Input | Meaning | Default |
|---|---|---|
| `workspace` | the bnd workspace, relative to the repository | `.` |
| `mode` | `each` or `all` ([modes](#function-4-apply)) | `each` |
| `scope` | default scope for the run; empty uses `-update-policy` | — |
| `only` | `groupId:artifactId` patterns | all proposed |
| `trivy-report`, `sbom` | apply the fixes for this Trivy report instead of all updates | — |
| `build-command` | build after resolving; a failing build reverts the update | none |
| `cli-jar` / `cli-version` | the CLI to use: a local jar, or this version from Maven Central (a `-SNAPSHOT` from the Central snapshot repository; the download is checked against the repository's checksum) | `0.1.0-SNAPSHOT` |
| `create-pull-request` | open/update the pull request | `true` |
| `branch`, `title`, `labels` | of the pull request; the branch is reused by later runs | `bnd-update/updates`, `bnd update: dependency updates`, `dependencies` |
| `token` | for pushing and opening the pull request | `github.token` |
| `fail-on-reverted` | fail the job when an update had to be reverted (after the pull request for the others) | `false` |

Outputs: `exit-code` (of `apply`), `report` (path of the Markdown report), `pull-request-url`.

Things to know:

- **Java 21** must be on the runner (`actions/setup-java`), plus whatever the build command needs.
- **Build the workspace before the action** (`./gradlew assemble`): bndruns that run the
  workspace's own bundles only resolve when those are built.
- The repository must allow GitHub Actions to create pull requests (*Settings → Actions →
  General → Workflow permissions*).
- **No CI on the pull request with the default token.** GitHub does not start workflows for
  events caused by `GITHUB_TOKEN`, so a pull request opened with it gets no checks. Pass a GitHub
  App token or a fine-grained personal token as `token` to get them — the build in `apply` has
  already run, but the full pipeline (OSGi tests, CodeQL) should run on the pull request too.
- Commits are **signed off** (`Signed-off-by`), so DCO checks pass.
- This repository uses the action on itself: `.github/workflows/bnd-update.yml` (weekly, micro,
  `each`, with a Gradle build).

## After an update: resolve every bndrun

**After any change to a `.mvn` index or a `-buildpath` version — by this tool, by the Bndtools
repository view or by hand — resolve every bndrun of the workspace before committing.**

An update can make a bndrun unresolvable: when a bundle imports a package with a narrow version
range (`Import-Package: com.fasterxml.jackson.databind;version="[2.19,2.20)"`), a newer provider
no longer satisfies it. It can also change what *other* bndruns resolve to. Resolving only the
bndruns that obviously contain the updated library is not enough.

Check first, without writing:

```
java -jar org.gecko.bnd.update.cli.jar resolve --format markdown
```

lists for every bndrun whether it resolves, what changes, and — if it does not resolve — the
requirements that block it. Then write the new `-runbundles` with Gradle (bnd workspace plugin):

```
./gradlew resolve
```

which resolves every bndrun of every project and updates the files. Then build and run the OSGi
tests (`./gradlew build testOSGi`) and review the changed `-runbundles` in the diff.

`apply` does this itself: it keeps an update only when **all** bndruns still resolve (and the
build passes, with `--build-command`), and writes the new `-runbundles`.

## Limits

- **Only Maven repositories.** Versions come from `MavenBndRepository` indexes. Bundles from p2,
  OBR or file repositories get no update proposal; their vulnerabilities are reported without a
  fix version unless the SBOM maps them to Maven coordinates (`maven.<bsn>` in `-sbom`).
- **Fix recognition reads the fixed-version list**, not the advisory's exact ranges — see
  [Choosing the fix version](#choosing-the-fix-version).
- **Resolving is not running.** `resolve` and `apply` prove that the bndruns resolve; whether
  the application behaves is for the build and the OSGi tests to show — run them before merging.
- **`apply` changes only text indexes.** Pom indexes and `-buildpath` versions of embedded
  libraries are reported, not changed.
- **Network.** Every library costs a metadata request per repository that holds it; large
  workspaces with many repositories take a while.

## Roadmap

Tracked in [#31](https://github.com/geckoprojects-org/org.gecko.bnd.sbom/issues/31):

- publish the Maven and Gradle plugins from Jenkins (#47)
- optional: report the SBOM's dependencies to GitHub for Dependabot alerts (#32)
