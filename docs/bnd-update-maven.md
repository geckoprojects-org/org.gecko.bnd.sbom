# bnd update with Maven

For projects built with the bnd Maven plugins, `bnd-update-maven-plugin` runs the
[vulnerabilities function](bnd-update.md#function-2-vulnerabilities): for every library a Trivy
report lists as vulnerable, it finds the smallest version in the project's Maven repositories
that fixes all its vulnerabilities and lies within the version policy.

A runnable project with the SBOM, Trivy and the plugin is
[examples/maven-sbom](../examples/maven-sbom/README.md).

## What it does and what not

| | Maven project | bnd workspace (Gradle) |
|---|---|---|
| Where the versions live | `pom.xml` | `.mvn` indexes in `cnf/` |
| Who finds newer versions | Dependabot, Renovate, `versions-maven-plugin` | `bnd update` (`updates`) |
| Who changes them | Dependabot, Renovate, the developer | `bnd update` (`apply`) |
| Who re-resolves the bndruns | `bnd-resolver-maven-plugin` | `bnd update` (`apply`), `./gradlew resolve` |
| Fix versions for a Trivy report | **`bnd-update-maven-plugin`** | `bnd update` (`vulnerabilities`) |

In a Maven project the dependencies are in the `pom.xml`, which the common tools already update.
What they do not do is tell you which version within *your* version policy fixes a
vulnerability, and where in the OSGi application the library sits. That is what the plugin adds.
It has no `apply` goal.

## Setup

The SBOM comes from `bnd-export-maven-plugin` with the exporter, see
[SBOMs with Maven](sbom-maven.md). Then add the plugin:

```xml
<plugin>
    <groupId>org.geckoprojects.bnd</groupId>
    <artifactId>bnd-update-maven-plugin</artifactId>
    <version><!-- version --></version>
    <configuration>
        <trivyReport>${project.basedir}/trivy.json</trivyReport>
        <sbom>${project.build.directory}/app.bndrun.cdx.json</sbom>
        <scope>micro</scope>
        <policy>com.fasterxml.jackson.core:*;scope=minor</policy>
        <failOn>unfixable</failOn>
    </configuration>
    <executions>
        <execution>
            <goals>
                <goal>vulnerabilities</goal>
            </goals>
        </execution>
    </executions>
</plugin>
```

The goal binds to the `verify` phase. For `-SNAPSHOT` versions add the Central snapshot
repository as plugin repository (see [SBOMs with Maven](sbom-maven.md#2-the-pomxml)).

## Running it

```
mvn package                                                     # the SBOM: target/app.bndrun.cdx.json
trivy sbom --format json --output trivy.json target/app.bndrun.cdx.json
mvn verify                                                      # the fixes: target/bnd-update/
```

Without Trivy, with the example's sample report:

```
mvn verify -Dbnd-update.trivy=trivy-sample.json
```

- `org.slf4j:slf4j-api` 2.0.17 → fixed by **2.0.18** (micro)
- `org.apache.felix:org.apache.felix.framework` 7.0.5 → needs a **major** update (8.0.0); the
  policy allows micro

The report goes to `target/bnd-update/vulnerabilities.md` (or `.json`), and every library gets a
warning or an error in the build log.

## Parameters

| Parameter | Property | Meaning | Default |
|---|---|---|---|
| `trivyReport` | `bnd-update.trivy` | Trivy JSON report (`trivy sbom --format json`) | required |
| `sbom` | `bnd-update.sbom` | the SBOM the report was made from; adds where each library sits | none |
| `scope` | `bnd-update.scope` | default scope: `micro`, `minor`, `major` | `micro` |
| `policy` | `bnd-update.policy` | per-library scopes in the `-update-policy` syntax, e.g. `com.fasterxml.jackson.core:*;scope=minor` | none |
| `format` | `bnd-update.format` | `markdown` or `json` | `markdown` |
| `failOn` | `bnd-update.failOn` | `none`; `unfixable`: fail when a library has no fix within the policy; `vulnerable`: fail on any finding | `none` |
| `skip` | `bnd-update.skip` | skip the goal | `false` |

Every parameter can be set on the command line through its property, e.g.
`mvn verify -Dbnd-update.failOn=unfixable -Dbnd-update.scope=minor`.

The versions on offer come from the project's Maven repositories, resolved by Maven itself, with
the mirrors, proxies and credentials of `settings.xml`.

## Which `failOn` to use

| Setting | The build fails when | Use for |
|---|---|---|
| `none` | never | local runs, reports only |
| `unfixable` | a vulnerable library has no fix within the policy (`OUTSIDE_POLICY`, `NO_FIX`) | CI: something needs a decision (widen the policy, replace the library, accept the risk) |
| `vulnerable` | any vulnerable library is found, even with a fix available | release builds that must not ship known vulnerabilities |

On Jenkins, run it inside `catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE')` to mark
the build unstable instead of failed, as
[examples/maven-sbom/Jenkinsfile](../examples/maven-sbom/Jenkinsfile) does.

## After an update

When a version in the `pom.xml` changes, re-resolve the bndruns with
`bnd-resolver-maven-plugin` and commit the new `-runbundles`, then export the SBOM again. See
[After an update](bnd-update.md#after-an-update-resolve-every-bndrun).
