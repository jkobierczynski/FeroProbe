#!/bin/sh
# Build the feroprobe(1) man page, docs/feroprobe.1, from docs/manual.md.
#
# docs/manual.md is the source; the man page is generated from it and
# committed, so it can be installed without pandoc. Run this script after
# changing the manual and commit both files together.
#
# Needs pandoc (2.x or 3.x). Usage, from the repository root or anywhere:
#
#   scripts/build-manpage.sh            # writes docs/feroprobe.1
#   man -l docs/feroprobe.1             # preview it
#
# Installing: copy docs/feroprobe.1 to a man1 directory, e.g.
#   sudo install -m 644 docs/feroprobe.1 /usr/local/share/man/man1/
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
src="$root/docs/manual.md"
out="$root/docs/feroprobe.1"
version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/Cargo.toml" | head -n 1)

if ! command -v pandoc >/dev/null 2>&1; then
    echo "build-manpage.sh: pandoc is needed (e.g. apt install pandoc)" >&2
    exit 1
fi

tmp=$(mktemp)
trap 'rm -f "$tmp" "$tmp.man"' EXIT

# A man page starts with NAME; the manual's title and table of contents
# only make sense on the web, so everything before "## Synopsis" is
# replaced by a NAME section.
{
    printf '## Name\n\nferoprobe - fast, nmap-style network scanner written in Rust\n\n'
    sed -n '/^## Synopsis$/,$p' "$src"
} >"$tmp"

pandoc "$tmp" \
    --from gfm \
    --to man \
    --standalone \
    --shift-heading-level-by=-1 \
    --metadata title=FEROPROBE \
    --metadata section=1 \
    --metadata header="FeroProbe Reference Manual" \
    --metadata footer="FeroProbe $version" \
    --metadata date= \
    --output "$tmp.man"

# Man pages write section titles in capitals (NAME, SYNOPSIS, ...).
awk '/^\.SH /{ print toupper($0); next } { print }' "$tmp.man" >"$out"
rm -f "$tmp.man"

echo "wrote $out"
