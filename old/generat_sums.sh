#!/bin/bash
# =============================================================================
# SecureSeaHorse SIEM -- SHA256SUMS Generator
# =============================================================================
# Generates a signed SHA256SUMS file covering every release artifact.
#
# Usage:
#   ./generate_sums.sh [VERSION]                    # Plain sums file
#   ./generate_sums.sh [VERSION] --sign <keyid>     # Also produce detached sig
#
# Example:
#   cd SecureSeaHorse-v3.1.4/
#   ./generate_sums.sh 3.1.4 --sign A4F2C19
#
# Output:
#   SHA256SUMS         -- plain text, sha256sum -c compatible
#   SHA256SUMS.asc     -- detached PGP signature (if --sign used)
# =============================================================================

set -eu

VERSION="${1:-3.1.4}"
SIGN=""
KEYID=""

# Parse optional --sign flag
shift || true
while [ $# -gt 0 ]; do
    case "$1" in
        --sign)
            SIGN="yes"
            KEYID="${2:-}"
            shift 2
            ;;
        *)
            echo "Unknown flag: $1" >&2
            exit 1
            ;;
    esac
done

OUT="SHA256SUMS"
REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_ROOT"

echo "Generating SHA256SUMS for SecureSeaHorse v${VERSION}..."
echo ""

# Header
cat > "$OUT" <<EOF
# SecureSeaHorse SIEM v${VERSION} -- SHA-256 Sums
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ") UTC
# Host: $(hostname -s)
#
# Verify with:
#   sha256sum -c SHA256SUMS
#
# Sums are provided for every source file, config file, installer script,
# and compiled binary present in the release. If --sign was passed, a
# detached PGP signature is written alongside as SHA256SUMS.asc.

EOF

# --- Release archives (if present) ---
for pattern in \
    "SecureSeaHorse-v${VERSION}.tar.gz" \
    "SecureSeaHorse-v${VERSION}.zip" \
    "SecureSeaHorse-v${VERSION}-Setup.exe" \
    "seahorse-server_${VERSION}_amd64.deb" \
    "seahorse-client_${VERSION}_amd64.deb"
do
    if [ -f "$pattern" ]; then
        echo "# Release archive: $pattern" >> "$OUT"
        sha256sum "$pattern" >> "$OUT"
        echo "" >> "$OUT"
    fi
done

# --- Compiled binaries (from build/ if present) ---
if [ -d build ]; then
    echo "# ---- Compiled binaries ----" >> "$OUT"
    for b in build/SeaHorseServer build/SeaHorseClient \
             build/SeaHorseServer.exe build/SeaHorseClient.exe \
             build/Release/SeaHorseServer.exe build/Release/SeaHorseClient.exe
    do
        if [ -f "$b" ]; then
            sha256sum "$b" >> "$OUT"
        fi
    done
    echo "" >> "$OUT"
fi

# --- Top-level documents ---
{
    echo "# ---- Top-level documents ----"
    for f in README.md LICENSE.txt CMakeLists.txt .gitignore \
             RELEASE_NOTES_v${VERSION}.md CHANGELOG.md; do
        [ -f "$f" ] && sha256sum "$f"
    done
    echo ""
} >> "$OUT"

# --- Documentation ---
{
    echo "# ---- Documentation ----"
    find docs -type f -name "*.md" 2>/dev/null | sort | while read -r f; do
        sha256sum "$f"
    done
    echo ""
} >> "$OUT"

# --- Installer scripts ---
{
    echo "# ---- Installer scripts ----"
    find installer -type f 2>/dev/null | sort | while read -r f; do
        sha256sum "$f"
    done
    echo ""
} >> "$OUT"

# --- Configuration templates ---
{
    echo "# ---- Configuration templates ----"
    for f in config/server.conf config/client.conf config/rules.conf; do
        [ -f "$f" ] && sha256sum "$f"
    done
    echo ""
} >> "$OUT"

# --- Server sources ---
{
    echo "# ============================================================================="
    echo "# SERVER SOURCES  (src/server/)"
    echo "# ============================================================================="
    find src/server -type f \( -name "*.cpp" -o -name "*.h" \) 2>/dev/null | sort | while read -r f; do
        sha256sum "$f"
    done
    echo ""
} >> "$OUT"

# --- Client sources ---
{
    echo "# ============================================================================="
    echo "# CLIENT SOURCES  (src/client/)"
    echo "# ============================================================================="
    find src/client -type f \( -name "*.cpp" -o -name "*.h" \) 2>/dev/null | sort | while read -r f; do
        sha256sum "$f"
    done
    echo ""
} >> "$OUT"

# --- Threat intel feeds (if any) ---
if [ -d config/feeds ] && [ -n "$(find config/feeds -name '*.csv' -print -quit 2>/dev/null)" ]; then
    {
        echo "# ---- Threat intel feeds (bundled) ----"
        find config/feeds -type f -name "*.csv" 2>/dev/null | sort | while read -r f; do
            sha256sum "$f"
        done
        echo ""
    } >> "$OUT"
fi

# Footer
{
    echo "# ============================================================================="
    echo "# Total files:   $(grep -c '^[0-9a-f]\{64\}' "$OUT")"
    echo "# Generator:     generate_sums.sh $(cat "$0" | sha256sum | cut -c1-16)"
    echo "# ============================================================================="
} >> "$OUT"

echo "Wrote: $OUT"
echo "Total hashes: $(grep -c '^[0-9a-f]\{64\}' "$OUT")"

# --- Optional PGP signature ---
if [ "$SIGN" = "yes" ]; then
    if ! command -v gpg >/dev/null 2>&1; then
        echo "ERROR: gpg not found; cannot sign." >&2
        exit 1
    fi
    if [ -z "$KEYID" ]; then
        echo "ERROR: --sign requires a key id argument." >&2
        exit 1
    fi
    echo ""
    echo "Signing with key $KEYID..."
    rm -f "$OUT.asc"
    gpg --batch --yes --armor --detach-sign --local-user "$KEYID" --output "$OUT.asc" "$OUT"
    echo "Wrote: $OUT.asc"
    echo ""
    echo "Verify with:"
    echo "  gpg --verify $OUT.asc $OUT"
fi

# --- Self-verify ---
echo ""
echo "Verifying generated sums..."
if sha256sum -c "$OUT" --quiet --ignore-missing; then
    echo "OK -- all files verified."
else
    echo "ERROR -- self-verification failed." >&2
    exit 1
fi
