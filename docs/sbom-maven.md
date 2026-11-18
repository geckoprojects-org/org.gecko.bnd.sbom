# SBOMs in a Maven build

Projects built with the bnd Maven plugins export the SBOM with bnd's own
`bnd-export-maven-plugin`. The exporter is added to it as a plugin dependency. No plugin of
this repository is needed for the SBOM.

A complete, runnable project is [examples/maven-sbom](../examples/maven-sbom/README.md). The
options of the exporter are in the [reference](sbom-exporter.md).

## What you get

```
mvn package
```

writes `target/app.bndrun.cdx.json`, the SBOM of `app.bndrun`.

## 1. The bndrun

The bndrun registers the exporter and configures it. The plugin is on the class path of
`bnd-export-maven-plugin`, so no `path:=` is needed:

```
-runfw: org.apache.felix.framework;version='[7.0.5,7.0.5]'
-runee: JavaSE-21
-runrequires: bnd.identity;id='my.application'
-runbundles: \
	my.application;version='[1.0.0,1.0.1)',\
	slf4j.api;version='[2.0.17,2.0.18)'

-plugin.sbom: org.gecko.bnd.sbom.SbomExporter
-sbom: level=medium, validate=bsi-tr-03183-2
```

The bundles come from the dependencies of the `pom.xml`, as usual for `bnd-export-maven-plugin`
and `bnd-resolver-maven-plugin`.

## 2. The pom.xml

```xml
<properties>
    <bnd.version>7.4.0</bnd.version>
    <gecko.bnd.version><!-- version of org.gecko.bnd.sbom --></gecko.bnd.version>
</properties>

<build>
    <plugins>
        <plugin>
            <groupId>biz.aQute.bnd</groupId>
            <artifactId>bnd-export-maven-plugin</artifactId>
            <version>${bnd.version}</version>
            <configuration>
                <bndruns>
                    <bndrun>app.bndrun</bndrun>
                </bndruns>
                <exporter>bnd.sbom</exporter>
                <!-- export the -runbundles as they are; see below -->
                <resolve>false</resolve>
            </configuration>
            <executions>
                <execution>
                    <goals>
                        <goal>export</goal>
                    </goals>
                </execution>
            </executions>
            <dependencies>
                <!-- the SBOM exporter -->
                <dependency>
                    <groupId>org.geckoprojects.bnd</groupId>
                    <artifactId>org.gecko.bnd.sbom</artifactId>
                    <version>${gecko.bnd.version}</version>
                </dependency>
            </dependencies>
        </plugin>
    </plugins>
</build>
```

For a `-SNAPSHOT` version of the exporter, add the Central snapshot repository as plugin
repository:

```xml
<pluginRepositories>
    <pluginRepository>
        <id>central-snapshots</id>
        <url>https://central.sonatype.com/repository/maven-snapshots/</url>
        <releases><enabled>false</enabled></releases>
        <snapshots><enabled>true</enabled></snapshots>
    </pluginRepository>
</pluginRepositories>
```

## 3. Resolve or not

`<resolve>false</resolve>` exports the `-runbundles` that are in the bndrun. With
`<resolve>true</resolve>` the plugin resolves first and the SBOM describes the result of that
resolution. Choose the one that matches what you ship: if the application is launched from the
same resolution, `true`; if the checked-in `-runbundles` are what is shipped, `false` and
`bnd-resolver-maven-plugin` to keep them current.

## 4. Several bndruns

`bnd-export-maven-plugin` exports every bndrun listed under `<bndruns>`. Each gets its own SBOM
in `target/`:

```xml
<bndruns>
    <bndrun>app.bndrun</bndrun>
    <bndrun>app-cloud.bndrun</bndrun>
</bndruns>
```

## 5. Attaching the SBOM to the build

To publish the SBOM with the project's artifacts, attach it with the `build-helper-maven-plugin`:

```xml
<plugin>
    <groupId>org.codehaus.mojo</groupId>
    <artifactId>build-helper-maven-plugin</artifactId>
    <executions>
        <execution>
            <id>attach-sbom</id>
            <phase>package</phase>
            <goals>
                <goal>attach-artifact</goal>
            </goals>
            <configuration>
                <artifacts>
                    <artifact>
                        <file>${project.build.directory}/app.bndrun.cdx.json</file>
                        <type>json</type>
                        <classifier>cyclonedx</classifier>
                    </artifact>
                </artifacts>
            </configuration>
        </execution>
    </executions>
</plugin>
```

`cyclonedx` as classifier and `json` as type is the convention of the CycloneDX Maven plugin,
which tools that look for a published SBOM expect.

## Not to be confused with the POM-based SBOM

The CycloneDX Maven plugin, and tools like Trivy on a `pom.xml`, derive an SBOM from the
project's Maven dependencies. For an OSGi application that is the build path, not what runs.
The SBOM of the bndrun describes the resolved application. For the bundles you publish, the
scopes in their POMs still matter: see [Maven scopes](maven-scopes.md).

## Next steps

- Scan the SBOM in CI: [SBOMs in CI](sbom-ci.md).
- Find the fix versions for what the scan reports: [bnd update with Maven](bnd-update-maven.md).
