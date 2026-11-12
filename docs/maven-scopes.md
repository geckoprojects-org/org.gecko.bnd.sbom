# Maven dependency scopes in bnd-generated POMs

bnd writes a `pom.xml` into every bundle it releases (`-pom`). This page explains why the
dependency scopes in that POM matter for SBOMs, and the rules we apply in bnd workspaces.

## Why the scopes matter

By default bnd turns **every `-buildpath` entry into a `<dependency>` with scope `compile`**.
For an OSGi bundle that is rarely right: the build path is what the code compiles against,
while at runtime the framework resolves packages and capabilities, not Maven artifacts.

The POM is not only read by Maven. Tools that build an SBOM from a project's POM take its
dependencies from there — directly, and transitively from the published POMs of everything
it depends on. With Trivy 0.76.2 we checked:

| Scope in the POM | In the SBOM Trivy derives from it |
|---|---|
| `compile` | yes |
| `runtime` | yes |
| `provided` | no |
| `test` | no |
| `<optional>true</optional>` | no |

The same holds transitively. A project that depends on `biz.aQute.bnd:biz.aQute.bndlib:7.4.0`
gets every `compile` dependency of bndlib's POM into its SBOM, but none of the ones bndlib
declares as `provided` (`org.osgi.namespace.*`). bnd itself uses `provided` this way.

So a bundle whose POM lists annotation jars, framework APIs or libraries it carries inside as
`compile` dependencies makes every consumer's SBOM larger than the software that actually
runs, and every vulnerability scan on it reports findings for artifacts that are not there.
Wrong scopes are not cosmetic: they produce false positives downstream, and they hide which
dependencies are real.

The SBOM this exporter writes is not affected — it is built from the resolved `-runbundles`
and their manifests, not from POM dependencies. Neither is a scan of finished jars or images,
which identifies artifacts by the `pom.properties` inside the jars. The scopes matter for
everyone who consumes our bundles **through Maven or Gradle**.

## The rules

### 1. Annotations and specification APIs: `provided`

Build-time annotations (`org.osgi.annotation.versioning`, `org.osgi.annotation.bundle`,
`org.osgi.service.component.annotations`, `org.osgi.service.metatype.annotations`,
`biz.aQute.bnd.annotation`) have `CLASS` retention; nothing of them exists at runtime.
Specification APIs such as `osgi.core` or `org.osgi.framework` are provided by the framework
the bundle runs in. In both cases the consumer's runtime brings the classes, so the bundle
must not drag the artifacts along.

```
-buildpath: \
	org.osgi.annotation.versioning;maven-scope=provided,\
	org.osgi.service.component.annotations;maven-scope=provided,\
	osgi.core;maven-scope=provided,\
	org.eclipse.emf.ecore
```

When a project's whole build path is like that — a bnd plugin, for which bnd is the runtime —
set the default for the project instead:

```
-maven-scope: provided
```

### 2. Libraries inlined into the bundle: `maven-optional=true`

A library whose classes the bundle carries inside — pulled in with `-conditionalpackage`,
`Private-Package` or `-includeresource: @lib.jar!/...` — is not a dependency: it is part of
the bundle. Listing it in the POM would make Maven consumers load it a second time, and SBOM
tools would report it twice. `maven-optional=true` makes bnd leave the entry out of the POM
entirely.

```
-buildpath: \
	org.osgi.util.promise;maven-optional=true

-conditionalpackage: org.osgi.util.*
```

The library does not disappear from the SBOM: the exporter finds it in the bundle and lists it
as an embedded component with its original Maven coordinates (`osgi:embedded:in`).

### 3. Libraries needed at runtime: `compile`

A library the bundle imports packages from and that has to be installed next to it —
EMF for a Fennec bundle, Jackson for a REST provider — is a real dependency. It stays
`compile`, the default, so Maven consumers get it and their SBOMs list it.

## Applying the rules in a workspace

- Shared build path entries belong in the workspace library (for Fennec: `-buildpath.base` in
  the library's `workspace.bnd`); setting `maven-scope=provided` there fixes every project at
  once.
- Per project, annotate the entries that are not obvious: inlined libraries with
  `maven-optional=true`, framework-provided APIs with `maven-scope=provided`.
- `-maven-dependencies:` (empty) drops the whole `<dependencies>` section. Use it only as a
  stop-gap, for example when the build path refers to snapshots that may not appear in a
  release POM; it removes the correct dependencies as well.

## Checking the result

Look at the POM bnd generated:

```
unzip -p generated/<bsn>.jar 'META-INF/maven/*/*/pom.xml'
```

And see what an SBOM tool derives from it:

```
trivy fs --format cyclonedx --list-all-pkgs pom.xml
```

Only the libraries a consumer really needs at runtime should remain.

## References

- bnd: [`-maven-scope`](https://bnd.bndtools.org/instructions/maven_scope.html),
  [`-maven-dependencies`](https://bnd.bndtools.org/instructions/maven_dependencies.html)
  (`maven-scope` and `maven-optional` on `-buildpath` entries)
- Maven: [dependency scope](https://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html#Dependency_Scope)
