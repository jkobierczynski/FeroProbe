#!/bin/sh
# Build the man pages from their Markdown sources:
#
#   docs/manual.md          -> docs/feroprobe.1       (feroprobe(1))
#   docs/feroprobe-diff.md  -> docs/feroprobe-diff.1  (feroprobe-diff(1))
#
# The Markdown files are the sources; the man pages are generated from them
# and committed, so they can be installed without pandoc. Run this script
# after changing either source and commit the sources and pages together.
#
# Needs pandoc (2.x or 3.x). Usage, from the repository root or anywhere:
#
#   scripts/build-manpage.sh            # writes both man pages
#   man -l docs/feroprobe.1             # preview one
#
# Installing: copy the .1 files to a man1 directory, e.g.
#   sudo install -m 644 docs/feroprobe.1 docs/feroprobe-diff.1 /usr/local/share/man/man1/
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/Cargo.toml" | head -n 1)

if ! command -v pandoc >/dev/null 2>&1; then
    echo "build-manpage.sh: pandoc is needed (e.g. apt install pandoc)" >&2
    exit 1
fi

tmp=$(mktemp)
trap 'rm -f "$tmp" "$tmp.man"' EXIT

# build SOURCE OUTPUT TITLE NAME-LINE
build() {
    src="$root/docs/$1"
    out="$root/docs/$2"
    # A man page starts with NAME; the source's title and table of contents
    # only make sense on the web, so everything before "## Synopsis" is
    # replaced by a NAME section.
    {
        printf '## Name\n\n%s\n\n' "$4"
        sed -n '/^## Synopsis$/,$p' "$src"
    } >"$tmp"

    pandoc "$tmp" \
        --from gfm \
        --to man \
        --standalone \
        --shift-heading-level-by=-1 \
        --metadata title="$3" \
        --metadata section=1 \
        --metadata header="FeroProbe Reference Manual" \
        --metadata footer="FeroProbe $version" \
        --metadata date= \
        --output "$tmp.man"

    # Man pages write section titles in capitals (NAME, SYNOPSIS, ...).
    awk '/^\.SH /{ print toupper($0); next } { print }' "$tmp.man" >"$out"
    rm -f "$tmp.man"
    echo "wrote $out"
}

build manual.md feroprobe.1 FEROPROBE \
    "feroprobe - fast, nmap-style network scanner written in Rust"
build feroprobe-diff.md feroprobe-diff.1 FEROPROBE-DIFF \
    "feroprobe-diff - compare two FeroProbe or nmap scan reports"
