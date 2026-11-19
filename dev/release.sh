#!/usr/bin/env bash
# Release mcp-calchas.
#
#   dev/release.sh <version>                      dry run: set version, build, check, test-install; upload nothing
#   dev/release.sh <version> --upload             also upload to PyPI, commit the version bump and tag v<version>
#   dev/release.sh <version> --upload --testpypi  upload to TestPyPI instead (no commit, no tag)
#
# Upload credentials come from ~/.pypirc or TWINE_USERNAME=__token__ / TWINE_PASSWORD=<pypi token>.
# A dry run restores calchas/__about__.py afterwards, so it leaves the working tree untouched.
set -euo pipefail

usage() { sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
[ $# -ge 1 ] || usage
VERSION="$1"; shift
UPLOAD=0; TESTPYPI=0
for a in "$@"; do
  case "$a" in
    --upload) UPLOAD=1 ;;
    --testpypi) TESTPYPI=1 ;;
    *) usage ;;
  esac
done
[ "$TESTPYPI" = 1 ] && [ "$UPLOAD" = 0 ] && { echo "--testpypi only makes sense with --upload" >&2; exit 1; }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PY="$ROOT/.venv/bin/python"
ABOUT="calchas/__about__.py"
PKG="mcp-calchas"
step() { printf '\n==> %s\n' "$*"; }
die() { printf 'ERROR: %b\n' "$*" >&2; exit 1; }

# ---- 1. preconditions --------------------------------------------------------
step "check preconditions"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+((a|b|rc)[0-9]+|\.dev[0-9]+|\.post[0-9]+)?$ ]] \
  || die "version '$VERSION' is not a PEP 440 release like 0.1.0, 0.2.0.dev1, 0.2.0rc1"
[ -x "$PY" ] || die "missing $PY (python3 -m venv .venv && .venv/bin/pip install -e . build twine)"
"$PY" -c "import build, twine" 2>/dev/null || die "install build tools: .venv/bin/pip install build twine"
[ -z "$(git status --porcelain)" ] || die "working tree is not clean; commit or stash first"
git rev-parse -q --verify "refs/tags/v$VERSION" >/dev/null && die "git tag v$VERSION already exists"

INDEX="https://pypi.org"; [ "$TESTPYPI" = 1 ] && INDEX="https://test.pypi.org"
code="$(curl -s -o /dev/null -w '%{http_code}' -m 20 "$INDEX/pypi/$PKG/$VERSION/json" || true)"
case "$code" in
  200) die "$PKG $VERSION already exists on $INDEX (versions can never be re-uploaded)" ;;
  404) echo "version $VERSION is free on $INDEX" ;;
  *)   [ "$UPLOAD" = 1 ] && die "could not query $INDEX (HTTP $code)"; echo "warning: could not query $INDEX (HTTP $code), continuing dry run" ;;
esac

# ---- 2. set version ----------------------------------------------------------
step "set version $VERSION"
OLD="$("$PY" -c "import re,sys; print(re.search(r'__version__ = \"([^\"]+)\"', open('$ABOUT').read()).group(1))")"
restore() { git checkout -q -- "$ABOUT"; }
# Dry runs (and failed uploads) put __about__.py back the way it was.
trap restore EXIT
sed -i.bak -E "s/^__version__ = \".*\"/__version__ = \"$VERSION\"/" "$ABOUT" && rm -f "$ABOUT.bak"
echo "$OLD -> $VERSION"

# ---- 3. build ----------------------------------------------------------------
step "build"
rm -rf dist build ./*.egg-info
"$PY" -m build >/dev/null
rm -rf build ./*.egg-info
ls -l dist
WHL="dist/mcp_calchas-$VERSION-py3-none-any.whl"
[ -f "$WHL" ] || die "expected $WHL was not produced"

# ---- 4. check ----------------------------------------------------------------
step "check metadata and contents"
"$PY" -m twine check dist/*
# Allow: python source, the declared package-data (sink/keyword_lexicon.json), and metadata — nothing else.
bad="$("$PY" -m zipfile -l "$WHL" | awk 'NR>1{print $1}' | grep -vE '^(calchas/.*\.py|calchas/sink/keyword_lexicon\.json|mcp_calchas-[^/]+\.dist-info/.*)$' || true)"
[ -z "$bad" ] || die "unexpected files in wheel:\n$bad"
leak="$(unzip -p "$WHL" 'calchas/*' | grep -aEn 'sk-[A-Za-z0-9._-]{20,}|mcphub_[A-Za-z0-9]{16,}' || true)"
[ -z "$leak" ] || die "possible secret in wheel:\n$leak"
echo "wheel contains only calchas/*.py, the sink keyword lexicon, and metadata; no secrets found"

# ---- 5. test install in a fresh venv ----------------------------------------
step "test install in a fresh venv"
TMP="$(mktemp -d)"
"$PY" -m venv "$TMP/venv"
"$TMP/venv/bin/pip" install -q "$WHL"
got="$("$TMP/venv/bin/calchas" --version)"
[ "$got" = "calchas $VERSION" ] || die "installed command reports '$got', expected 'calchas $VERSION'"
(cd "$TMP" && "$TMP/venv/bin/calchas" selftest >/dev/null) || die "selftest failed in the fresh install"
rm -rf "$TMP"
echo "$got; selftest passed"

if [ "$UPLOAD" = 0 ]; then
  step "dry run finished: dist/ holds the $VERSION build; $ABOUT restored to $OLD"
  exit 0
fi

# ---- 6. upload ---------------------------------------------------------------
if [ "$TESTPYPI" = 1 ]; then
  step "upload to TestPyPI"
  "$PY" -m twine upload --repository-url https://test.pypi.org/legacy/ dist/*
  step "done: pip install -i https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ $PKG==$VERSION"
  exit 0
fi

step "upload to PyPI"
"$PY" -m twine upload dist/*
trap - EXIT   # keep the new version in __about__.py

# ---- 7. commit and tag -------------------------------------------------------
step "commit and tag v$VERSION"
if ! git diff --quiet -- "$ABOUT"; then
  git add "$ABOUT"
  git commit -q -m "发布 v$VERSION"
fi
git tag -a "v$VERSION" -m "mcp-calchas $VERSION"
echo "committed and tagged v$VERSION (not pushed: git push origin calchas --tags)"
step "done: https://pypi.org/project/$PKG/$VERSION/"
