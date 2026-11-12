# bnd update: finding updates and fixes for bnd workspaces

`org.gecko.bnd.update` answers two questions for a bnd workspace:

1. **Which of our libraries have newer versions?** — independent of any vulnerability report.
2. **Which of our vulnerable libraries can be fixed, and with which version?** — for a Trivy
   report, using what the workspace's repositories actually offer.

Both only read. They change no file; applying updates is a separate step (see
[Roadmap](#roadmap)).

The same logic is available as a Java library, as a command line, and — planned — as Gradle and
Maven plugins and CI adapters. Everything in this document applies to all of them.

- [Why not Dependabot](#why-not-dependabot)
- [How it works](#how-it-works)
- [The version policy](#the-version-policy)
- [Choosing the fix version](#choosing-the-fix-version)
- [Command line](#command-line)
- [Using it as a library](#using-it-as-a-library)
- [In CI](#in-ci)
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

Workspace errors and warnings go to standard error; the report goes to standard output or the
output file. bnd's own logging is set to warnings (override with
`-Dorg.slf4j.simpleLogger.defaultLogLevel=info`).

### Exit codes

| Code | `updates` | `vulnerabilities` |
|---|---|---|
| 0 | nothing to update | nothing vulnerable |
| 1 | updates within the policy | every vulnerable library has a fix within the policy |
| 2 | — | at least one library has no fix within the policy (`OUTSIDE_POLICY` or `NO_FIX`) |
| 64 | usage error | usage error |
| 70 | internal error | internal error |

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
| `Reports` | JSON and Markdown renderings |

## In CI

The command line is the same everywhere; only how it is called differs. A typical job: export the
SBOMs, scan them with Trivy, run the check, publish the report.

**Jenkins**

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

**GitHub Actions**

```yaml
- run: |
    java -jar org.gecko.bnd.update.cli.jar vulnerabilities --trivy trivy.json \
      --sbom app/generated/sbom/app.bndrun.cdx.json --format markdown --output fixes.md
    cat fixes.md >> "$GITHUB_STEP_SUMMARY"
```

Ready-made adapters (a GitHub Action, a GitLab CI template, a Jenkins step) that also open
PRs/MRs are planned (#35, #38).

## After an update: resolve every bndrun

**After any change to a `.mvn` index or a `-buildpath` version — by this tool, by the Bndtools
repository view or by hand — resolve every bndrun of the workspace before committing.**

An update can make a bndrun unresolvable: when a bundle imports a package with a narrow version
range (`Import-Package: com.fasterxml.jackson.databind;version="[2.19,2.20)"`), a newer provider
no longer satisfies it. It can also change what *other* bndruns resolve to. Resolving only the
bndruns that obviously contain the updated library is not enough.

With Gradle (bnd workspace plugin):

```
./gradlew resolve
```

resolves every bndrun of every project and fails on the first one that does not resolve. Then
build and run the OSGi tests (`./gradlew build testOSGi`) and review the changed `-runbundles`
in the diff.

The planned `fix` step will do this itself: it proposes an update only when **all** bndruns still
resolve, and lists the result per bndrun in the PR/MR.

## Limits

- **Only Maven repositories.** Versions come from `MavenBndRepository` indexes. Bundles from p2,
  OBR or file repositories get no update proposal; their vulnerabilities are reported without a
  fix version unless the SBOM maps them to Maven coordinates (`maven.<bsn>` in `-sbom`).
- **Fix recognition reads the fixed-version list**, not the advisory's exact ranges — see
  [Choosing the fix version](#choosing-the-fix-version).
- **No compatibility check yet.** The policy limits the step size; whether the bndruns still
  resolve is checked by the `fix` step (planned) or by you ([above](#after-an-update-resolve-every-bndrun)).
- **Network.** Every library costs a metadata request per repository that holds it; large
  workspaces with many repositories take a while.

## Roadmap

Tracked in [#31](https://github.com/geckoprojects-org/org.gecko.bnd.sbom/issues/31):

- resolvability check of all bndruns (#34)
- `fix`: apply all or selected updates, resolve, build, report the result; GitHub Action that
  opens PRs (#35); GitLab CI and Jenkins adapters (#38)
- Gradle plugin (#36), Maven plugin (#37)
- optional: report the SBOM's dependencies to GitHub for Dependabot alerts (#32)
