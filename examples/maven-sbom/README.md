# Example: SBOM and vulnerability fixes with Maven

A project built with the bnd Maven plugins: `app.bndrun` runs `slf4j-api` on Apache Felix, its
bundles come from the `pom.xml` dependencies.

```
mvn package
```

exports the SBOM of `app.bndrun` with `bnd-export-maven-plugin` and the SBOM exporter as its
plugin dependency: `target/app.bndrun.cdx.json`. In the bndrun the exporter is registered with
`-plugin.sbom: org.gecko.bnd.sbom.SbomExporter`, and `-sbom: level=medium` adds hashes and
licenses. No plugin of our own is needed for the SBOM.

```
trivy sbom --format json --output trivy.json target/app.bndrun.cdx.json
mvn verify
```

scans the SBOM with Trivy and lets `bnd-update-maven-plugin` (goal `vulnerabilities`) find, for
every vulnerable library, the smallest version in the project's Maven repositories that fixes it
within the version policy: `target/bnd-update/vulnerabilities.md`, and a warning or error per
library in the build log.

Without Trivy, the sample report shows the two typical outcomes:

```
mvn verify -Dbnd-update.trivy=trivy-sample.json
```

- `org.slf4j:slf4j-api` 2.0.17 → fixed by **2.0.18** (micro)
- `org.apache.felix:org.apache.felix.framework` 7.0.5 → needs a **major** update (8.0.0); the
  policy allows micro

The findings in `trivy-sample.json` are made up; the versions they point to are real.

## Configuration of `bnd-update-maven-plugin`

| Parameter | Property | Meaning | Default |
|---|---|---|---|
| `trivyReport` | `bnd-update.trivy` | Trivy JSON report | required |
| `sbom` | `bnd-update.sbom` | the SBOM the report was made from; adds where each library sits | — |
| `scope` | `bnd-update.scope` | default scope: `micro`, `minor`, `major` | `micro` |
| `policy` | `bnd-update.policy` | per-library scopes, `-update-policy` syntax, e.g. `com.fasterxml.jackson.core:*;scope=minor` | — |
| `format` | `bnd-update.format` | `markdown` or `json` | `markdown` |
| `failOn` | `bnd-update.failOn` | `none`, `unfixable` (a library has no fix within the policy), `vulnerable` (any finding) | `none` |
| `skip` | `bnd-update.skip` | skip the goal | `false` |

Changing the versions in the `pom.xml` is left to Dependabot or the developer; afterwards
`bnd-resolver-maven-plugin` re-resolves the bndruns. See [docs/bnd-update.md](../../docs/bnd-update.md).
