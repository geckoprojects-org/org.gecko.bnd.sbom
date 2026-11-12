#!/usr/bin/env bash
#
# Copyright (c) 2026 Contributors to the Eclipse Foundation.
#
# This program and the accompanying materials are made
# available under the terms of the Eclipse Public License 2.0
# which is available at https://www.eclipse.org/legal/epl-2.0/
#
# SPDX-License-Identifier: EPL-2.0
#
# Contributors:
#     Data In Motion - initial API and implementation
#
# bnd update for any CI (Jenkins, GitLab CI, a shell): runs `bnd-update apply` in a bnd
# workspace, commits the verified updates on a branch, pushes it and opens - or updates - one
# pull request (GitHub) or merge request (GitLab). See docs/bnd-update.md.
#
# Needs bash, git, curl, Java 21. The workspace's own bundles must be built before (e.g.
# ./gradlew assemble), so that its bndruns resolve.
#
# Configuration, all through the environment:
#
#   BND_UPDATE_WORKSPACE  bnd workspace directory                         (default: .)
#   MODE                  each | all                                      (default: each)
#   SCOPE                 micro | minor | major; empty: -update-policy
#   ONLY                  groupId:artifactId patterns, comma separated
#   TRIVY_REPORT, SBOM    apply the fixes for this Trivy report (and SBOM)
#   BUILD_COMMAND         build to verify each update, e.g. './gradlew build -x test --no-daemon'
#   CLI_JAR               a bnd-update CLI jar; empty downloads CLI_VERSION
#   CLI_VERSION           org.geckoprojects.bnd:org.gecko.bnd.update.cli  (default: 0.1.0-SNAPSHOT)
#   BRANCH                branch of the pull/merge request                (default: bnd-update/updates)
#   BASE                  target branch; default: GitLab's CI_DEFAULT_BRANCH, Jenkins' CHANGE_TARGET
#                         or BRANCH_NAME, else the current branch
#   TITLE                 title of the request and the commit            (default: bnd update: dependency updates)
#   LABELS                labels, comma separated                          (default: dependencies)
#   GIT_NAME, GIT_EMAIL   commit identity; default: the git configuration  (Signed-off-by uses it)
#   DRY_RUN               true: apply and commit locally, show what would be pushed and requested
#   FAIL_ON_REVERTED      true: exit 2 when an update had to be reverted   (default: false)
#
#   GitHub:  GITHUB_TOKEN, GITHUB_REPOSITORY (owner/repo), GITHUB_API_URL (default https://api.github.com),
#            GITHUB_SERVER (default github.com)
#   GitLab:  GITLAB_TOKEN, CI_PROJECT_ID, CI_PROJECT_PATH, CI_API_V4_URL, CI_SERVER_URL (set by GitLab CI;
#            CI_SERVER_HOST is used when CI_SERVER_URL is not set)
#   Neither: the updates are committed locally only.
#
# Exit codes: 0 done (or nothing to do), 2 an update was reverted and FAIL_ON_REVERTED=true,
# 1 failure.

set -euo pipefail

WORKSPACE_DIR="${BND_UPDATE_WORKSPACE:-.}"
MODE="${MODE:-each}"
SCOPE="${SCOPE:-}"
ONLY="${ONLY:-}"
TRIVY_REPORT="${TRIVY_REPORT:-}"
SBOM="${SBOM:-}"
BUILD_COMMAND="${BUILD_COMMAND:-}"
CLI_JAR="${CLI_JAR:-}"
CLI_VERSION="${CLI_VERSION:-0.1.0-SNAPSHOT}"
BRANCH="${BRANCH:-bnd-update/updates}"
TITLE="${TITLE:-bnd update: dependency updates}"
LABELS="${LABELS:-dependencies}"
DRY_RUN="${DRY_RUN:-false}"
FAIL_ON_REVERTED="${FAIL_ON_REVERTED:-false}"

log() { printf '>> %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# ---- JSON without jq ------------------------------------------------------------------------

json_escape() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  printf '%s' "$s"
}

# first value of a numeric/string field in a JSON response
json_first() {
  local field=$1
  sed -n "s/.*\"$field\" *: *\"\{0,1\}\([^\",}]*\).*/\1/p" | head -1
}

labels_json() {
  local out="" l
  IFS=',' read -ra items <<< "$LABELS"
  for l in "${items[@]}"; do
    l="${l#"${l%%[![:space:]]*}"}"; l="${l%"${l##*[![:space:]]}"}"
    [ -n "$l" ] && out+="${out:+,}\"$(json_escape "$l")\""
  done
  printf '[%s]' "$out"
}

# ---- the CLI ----------------------------------------------------------------------------------

command -v java >/dev/null || die "Java 21 is required"
command -v git >/dev/null || die "git is required"
command -v curl >/dev/null || die "curl is required"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if [ -n "$CLI_JAR" ]; then
  JAR="$(cd "$(dirname "$CLI_JAR")" && pwd)/$(basename "$CLI_JAR")"
else
  base="org/geckoprojects/bnd/org.gecko.bnd.update.cli/$CLI_VERSION"
  if [[ "$CLI_VERSION" == *-SNAPSHOT ]]; then
    repo="https://central.sonatype.com/repository/maven-snapshots"
    meta="$(curl -fsSL "$repo/$base/maven-metadata.xml" | tr -d ' \n')"
    ts="$(printf '%s' "$meta" | sed -n 's:.*<timestamp>\([^<]*\)</timestamp>.*:\1:p')"
    bn="$(printf '%s' "$meta" | sed -n 's:.*<buildNumber>\([^<]*\)</buildNumber>.*:\1:p')"
    [ -n "$ts" ] && [ -n "$bn" ] || die "no snapshot of $CLI_VERSION in $repo"
    file="org.gecko.bnd.update.cli-${CLI_VERSION%-SNAPSHOT}-$ts-$bn.jar"
  else
    repo="https://repo.maven.apache.org/maven2"
    file="org.gecko.bnd.update.cli-$CLI_VERSION.jar"
  fi
  JAR="$TMP/$file"
  log "Downloading $file"
  curl -fsSL -o "$JAR" "$repo/$base/$file"
  expected="$(curl -fsSL "$repo/$base/$file.sha1")"
  echo "${expected%% *}  $JAR" | sha1sum -c --strict - >/dev/null || die "checksum of $file does not match"
fi

cd "$WORKSPACE_DIR"
[ -d cnf ] || die "$(pwd) is not a bnd workspace (no cnf directory)"
git diff --quiet && git diff --cached --quiet || die "the working tree has uncommitted changes; bnd update needs a clean checkout"

if [ -z "${BASE:-}" ]; then
  BASE="${CI_DEFAULT_BRANCH:-${CHANGE_TARGET:-${BRANCH_NAME:-$(git rev-parse --abbrev-ref HEAD)}}}"
fi
[ "$BASE" != "HEAD" ] || die "detached HEAD: set BASE to the target branch"

# ---- apply ------------------------------------------------------------------------------------

REPORT="$TMP/bnd-update.md"
args=(apply --mode "$MODE" --format markdown --output "$REPORT")
[ -n "$SCOPE" ] && args+=(--scope "$SCOPE")
[ -n "$ONLY" ] && args+=(--only "$ONLY")
[ -n "$TRIVY_REPORT" ] && args+=(--from-vulnerabilities "$TRIVY_REPORT")
[ -n "$SBOM" ] && args+=(--sbom "$SBOM")
[ -n "$BUILD_COMMAND" ] && args+=(--build-command "$BUILD_COMMAND")

log "bnd-update ${args[*]}"
code=0
java -jar "$JAR" "${args[@]}" || code=$?
[ -f "$REPORT" ] && cat "$REPORT"
case "$code" in
  0) log "Nothing to update."; exit 0 ;;
  1|2) ;;
  *) die "bnd-update apply failed with exit code $code" ;;
esac
# the copy for a CI artifact
[ -f "$REPORT" ] && cp "$REPORT" bnd-update-report.md

if git diff --quiet; then
  log "No file changed (every update was reverted or skipped)."
  [ "$code" = 2 ] && [ "$FAIL_ON_REVERTED" = true ] && exit 2
  exit 0
fi

# ---- commit -----------------------------------------------------------------------------------

identity=()
[ -n "${GIT_NAME:-}" ] && identity+=(-c "user.name=$GIT_NAME")
[ -n "${GIT_EMAIL:-}" ] && identity+=(-c "user.email=$GIT_EMAIL")
git checkout -q -B "$BRANCH"
git add -u
git "${identity[@]}" commit -q -s -m "$TITLE" -m "Applied and verified by bnd update: every bndrun resolves${BUILD_COMMAND:+, the build passes}."
log "Committed on $BRANCH: $(git log -1 --format='%h %s')"
git show --stat --format= HEAD | sed 's/^/   /'

BODY="$(head -c 60000 "$REPORT" 2>/dev/null || true)"

# ---- push and request -------------------------------------------------------------------------

mask() { sed -e "s#${1}#***#g"; }

if [ -n "${GITHUB_TOKEN:-}" ] && [ -n "${GITHUB_REPOSITORY:-}" ]; then
  api="${GITHUB_API_URL:-https://api.github.com}"
  server="${GITHUB_SERVER:-github.com}"
  owner="${GITHUB_REPOSITORY%%/*}"
  auth=(-H "Authorization: Bearer $GITHUB_TOKEN" -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28")
  existing="$(curl -fsSL "${auth[@]}" "$api/repos/$GITHUB_REPOSITORY/pulls?head=$owner:$BRANCH&state=open" | json_first number)"
  if [ "$DRY_RUN" = true ]; then
    if [ -n "$existing" ]; then request="update pull request #$existing"; else request="open a pull request into $BASE"; fi
    log "DRY_RUN: would push $BRANCH to $server/$GITHUB_REPOSITORY and $request"
    exit 0
  fi
  git push -q --force "https://x-access-token:${GITHUB_TOKEN}@${server}/${GITHUB_REPOSITORY}.git" "HEAD:refs/heads/$BRANCH" 2>&1 | mask "$GITHUB_TOKEN"
  if [ -n "$existing" ]; then
    curl -fsSL "${auth[@]}" -X PATCH "$api/repos/$GITHUB_REPOSITORY/pulls/$existing" \
      -d "{\"title\":\"$(json_escape "$TITLE")\",\"body\":\"$(json_escape "$BODY")\"}" >/dev/null
    number="$existing"
    log "Updated pull request #$number"
  else
    response="$(curl -fsSL "${auth[@]}" -X POST "$api/repos/$GITHUB_REPOSITORY/pulls" \
      -d "{\"title\":\"$(json_escape "$TITLE")\",\"head\":\"$(json_escape "$BRANCH")\",\"base\":\"$(json_escape "$BASE")\",\"body\":\"$(json_escape "$BODY")\"}")"
    number="$(printf '%s' "$response" | json_first number)"
    log "Opened pull request #$number"
  fi
  curl -fsSL "${auth[@]}" -X POST "$api/repos/$GITHUB_REPOSITORY/issues/$number/labels" -d "{\"labels\":$(labels_json)}" >/dev/null || true
  log "https://$server/$GITHUB_REPOSITORY/pull/$number"

elif [ -n "${GITLAB_TOKEN:-}" ] && [ -n "${CI_PROJECT_ID:-}" ]; then
  api="${CI_API_V4_URL:-https://gitlab.com/api/v4}"
  server="${CI_SERVER_URL:-https://${CI_SERVER_HOST:-gitlab.com}}"
  server="${server%/}"
  [ -n "${CI_PROJECT_PATH:-}" ] || die "CI_PROJECT_PATH is needed to push to GitLab"
  auth=(-H "PRIVATE-TOKEN: $GITLAB_TOKEN" -H "Content-Type: application/json")
  existing="$(curl -fsSL "${auth[@]}" "$api/projects/$CI_PROJECT_ID/merge_requests?state=opened&source_branch=$BRANCH" | json_first iid)"
  if [ "$DRY_RUN" = true ]; then
    if [ -n "$existing" ]; then request="update merge request !$existing"; else request="open a merge request into $BASE"; fi
    log "DRY_RUN: would push $BRANCH to $server/$CI_PROJECT_PATH and $request"
    exit 0
  fi
  git push -q --force "${server%%://*}://oauth2:${GITLAB_TOKEN}@${server#*://}/${CI_PROJECT_PATH}.git" "HEAD:refs/heads/$BRANCH" 2>&1 | mask "$GITLAB_TOKEN"
  if [ -n "$existing" ]; then
    curl -fsSL "${auth[@]}" -X PUT "$api/projects/$CI_PROJECT_ID/merge_requests/$existing" \
      -d "{\"title\":\"$(json_escape "$TITLE")\",\"description\":\"$(json_escape "$BODY")\"}" >/dev/null
    log "Updated merge request !$existing"
  else
    response="$(curl -fsSL "${auth[@]}" -X POST "$api/projects/$CI_PROJECT_ID/merge_requests" \
      -d "{\"source_branch\":\"$(json_escape "$BRANCH")\",\"target_branch\":\"$(json_escape "$BASE")\",\"title\":\"$(json_escape "$TITLE")\",\"description\":\"$(json_escape "$BODY")\",\"labels\":\"$(json_escape "$LABELS")\",\"remove_source_branch\":true}")"
    log "Opened merge request !$(printf '%s' "$response" | json_first iid)"
  fi

else
  log "No GITHUB_TOKEN/GITHUB_REPOSITORY or GITLAB_TOKEN/CI_PROJECT_ID: the updates are committed on $BRANCH locally only."
fi

[ "$code" = 2 ] && [ "$FAIL_ON_REVERTED" = true ] && exit 2
exit 0
