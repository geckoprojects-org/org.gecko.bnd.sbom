#!/usr/bin/env bash
# Publishes the build plugins, which are built outside the bnd workspace: the Maven plugin
# (maven-plugin/, bnd-update-maven-plugin) and the Gradle plugin (gradle-plugin/, the plugin
# org.geckoprojects.bnd.update and its marker). The Jenkinsfile runs it right after bnd has
# released the workspace, with the same environment, so the plugins go where the bundles go:
#
#   snapshot (DO_RELEASE unset/false)  <base-version>-SNAPSHOT  -> DIM Nexus dim-snapshot and,
#                                       with CS_USERNAME, the Central Portal's snapshot repository
#   release  (DO_RELEASE=true)          <base-version>, signed  -> DIM Nexus dim-release (unless
#                                       NEXUS_RELEASE=false) and dist/bundles, which the
#                                       Jenkinsfile's centralUpload() hands to the Portal together
#                                       with the bundles
#
# The version is the workspace's base-version (cnf/ext/fennec.bnd). The Maven plugin is built
# against the org.gecko.bnd.update jar of this very build, installed into the local repository
# first. Needs Java 21 and a built workspace (./gradlew build release).
#
# Environment: DO_RELEASE, NEXUS_RELEASE, NEXUS_USERNAME/NEXUS_PASSWORD, CS_USERNAME/CS_PASSWORD,
# GPG_PASSPHRASE (+ GNUPGHOME, GPG_KEY_ID) for releases, MAVEN_REPO_LOCAL (default .m2).
# For trials, the targets can be redirected: NEXUS_SNAPSHOT_URL, NEXUS_RELEASE_URL,
# CENTRAL_SNAPSHOT_URL, DIST_DIR (e.g. to file:// directories).

set -euo pipefail

log() { printf '>> %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

base="$(sed -n 's/^base-version:[[:space:]]*//p' cnf/ext/fennec.bnd | tr -d '[:space:]')"
[ -n "$base" ] || die "no base-version in cnf/ext/fennec.bnd"
RELEASE=false
[ "${DO_RELEASE:-false}" = true ] && RELEASE=true
if [ "$RELEASE" = true ]; then VERSION="$base"; else VERSION="$base-SNAPSHOT"; fi

NEXUS_SNAPSHOT_URL="${NEXUS_SNAPSHOT_URL:-https://devel.data-in-motion.biz/nexus/repository/dim-snapshot/}"
NEXUS_RELEASE_URL="${NEXUS_RELEASE_URL:-https://devel.data-in-motion.biz/nexus/repository/dim-release/}"
CENTRAL_SNAPSHOT_URL="${CENTRAL_SNAPSHOT_URL:-https://central.sonatype.com/repository/maven-snapshots/}"
DIST_DIR="${DIST_DIR:-$ROOT/dist/bundles}"
MAVEN_REPO_LOCAL="${MAVEN_REPO_LOCAL:-$ROOT/.m2}"

# targets: "<id> <url>"; the id selects the login in ci/maven-settings.xml and for Gradle
targets=()
if [ "$RELEASE" = true ]; then
  [ -n "${GPG_PASSPHRASE:-}" ] || die "a release must be signed: GPG_PASSPHRASE is not set"
  [ "${NEXUS_RELEASE:-true}" = false ] || targets+=("nexus $NEXUS_RELEASE_URL")
  mkdir -p "$DIST_DIR"
  targets+=("dist file://$(cd "$DIST_DIR" && pwd)")
else
  targets+=("nexus $NEXUS_SNAPSHOT_URL")
  [ -n "${CS_USERNAME:-}" ] && targets+=("central $CENTRAL_SNAPSHOT_URL")
fi
log "Plugins $VERSION -> ${targets[*]}"

login() { # id -> "user password" variables for Gradle
  case "$1" in
    nexus) printf '%s\n%s\n' "${NEXUS_USERNAME:-}" "${NEXUS_PASSWORD:-}" ;;
    central) printf '%s\n%s\n' "${CS_USERNAME:-}" "${CS_PASSWORD:-}" ;;
    *) printf '\n\n' ;;
  esac
}

# ---- Maven plugin ---------------------------------------------------------------------------

library=org.gecko.bnd.update/generated/org.gecko.bnd.update.jar
[ -f "$library" ] || die "$library is missing: build the workspace first"
tmp="$(mktemp -d)"
cp maven-plugin/pom.xml "$tmp/plugin-pom.xml"
trap 'cp "$tmp/plugin-pom.xml" maven-plugin/pom.xml; rm -rf "$tmp"' EXIT
# the POM bnd wrote into the jar (jar instead of unzip: only Java is required)
(cd "$tmp" && jar xf "$ROOT/$library" META-INF/maven)
pom="$(find "$tmp/META-INF/maven" -path '*/org.gecko.bnd.update/pom.xml' | head -1)"
[ -n "$pom" ] || die "$library has no Maven POM"
built="$(sed -n 's:^  <version>\(.*\)</version>:\1:p' "$pom" | head -1)"
[ "$built" = "$VERSION" ] || die "$library was built as $built, the plugins would be $VERSION (DO_RELEASE differs between the bnd build and this script?)"

# Maven itself, pinned: downloaded once, checked against its SHA-512, unpacked with tar (the
# agent needs neither Maven nor unzip)
MAVEN_VERSION=3.9.16
MAVEN_SHA512=831a8591fe20c8243b1dbe7d71e3244f31d1665b0804b2e825e38cbbe5ce0cafb8338851f90780735568773e0a6cd07bbec107cda0b896b008b861075358b6f6
maven_home="${MAVEN_CACHE:-$HOME/.cache/bnd-update}/apache-maven-$MAVEN_VERSION"
if [ ! -x "$maven_home/bin/mvn" ]; then
  log "Downloading Maven $MAVEN_VERSION"
  archive="$tmp/apache-maven-$MAVEN_VERSION-bin.tar.gz"
  curl -fsSL -o "$archive" "https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/$MAVEN_VERSION/apache-maven-$MAVEN_VERSION-bin.tar.gz"
  echo "$MAVEN_SHA512  $archive" | sha512sum -c --strict --quiet - || die "checksum of the Maven distribution does not match"
  mkdir -p "$(dirname "$maven_home")"
  tar xzf "$archive" -C "$tmp"
  rm -rf "$maven_home"
  mv "$tmp/apache-maven-$MAVEN_VERSION" "$maven_home"
fi

mvn=("$maven_home/bin/mvn" -B -ntp -s "$ROOT/ci/maven-settings.xml" -Dmaven.repo.local="$MAVEN_REPO_LOCAL")
(
  cd maven-plugin
  "${mvn[@]}" -q install:install-file -Dfile="$ROOT/$library" -DpomFile="$pom"
  "${mvn[@]}" -q org.codehaus.mojo:versions-maven-plugin:2.18.0:set -DnewVersion="$VERSION" -DgenerateBackupPoms=false
  "${mvn[@]}" -q org.codehaus.mojo:versions-maven-plugin:2.18.0:set-property -Dproperty=bnd-update.version -DnewVersion="$VERSION" -DgenerateBackupPoms=false
  profile=()
  if [ "$RELEASE" = true ]; then
    profile=(-Prelease)
    export MAVEN_GPG_PASSPHRASE="$GPG_PASSPHRASE"
    [ -n "${GPG_KEY_ID:-}" ] && profile+=(-Dgpg.keyname="$GPG_KEY_ID")
  fi
  tests=()
  for target in "${targets[@]}"; do
    read -r id url <<< "$target"
    log "Maven plugin -> $id"
    "${mvn[@]}" "${profile[@]}" "${tests[@]}" deploy -DaltDeploymentRepository="$id::$url"
    tests=(-DskipTests)
  done
)

# ---- Gradle plugin --------------------------------------------------------------------------

gradle=(./gradlew -p gradle-plugin --no-daemon -PpluginVersion="$VERSION")
sign=()
if [ "$RELEASE" = true ]; then
  sign=(-Psign=true)
  [ -n "${GPG_KEY_ID:-}" ] && sign+=(-Psigning.gnupg.keyName="$GPG_KEY_ID")
fi
first=build
for target in "${targets[@]}"; do
  read -r id url <<< "$target"
  log "Gradle plugin -> $id"
  { read -r user; read -r password; } < <(login "$id")
  # credentials and passphrase through the environment, not the command line
  env "ORG_GRADLE_PROJECT_targetUsername=$user" "ORG_GRADLE_PROJECT_targetPassword=$password" \
    "ORG_GRADLE_PROJECT_signing.gnupg.passphrase=${GPG_PASSPHRASE:-}" \
    "${gradle[@]}" "${sign[@]}" -PpublishUrl="$url" $first publishAllPublicationsToTargetRepository
  first=
done

log "Published the plugins $VERSION"
