#!/bin/sh
# apply.sh -- put the BBIWY look into an installed browser.
#
#   tools/theme/apply.sh <install-dir>
#
# <install-dir> is the directory holding `Browser/`. Nothing is compiled: four
# stylesheets are appended to the three entries they override, in the two
# `omni.ja` files (`Browser/omni.ja` and `Browser/browser/omni.ja`), each an
# ordinary zip. Replacing one entry takes about fifty milliseconds and leaves
# the other eight thousand alone. The upstream build injects its preferences
# the same way, so this is the archive's supported shape rather than a trick
# played on it.
#
# Running it twice is the same as running it once: the previous block is cut
# before the new one goes on.
#
# `bbiwy install` embeds the same four files and appends them under the same
# marker, so the two are interchangeable: either one, run over the other's
# result, replaces the block rather than adding a second. This script stays the
# design loop — it reads the stylesheets from the tree, so a change shows up
# without rebuilding the launcher. A release applies the same files to the
# source tree, so that what ships is what a reproducible build reproduces.
set -eu

MARK='/* ==== BBIWY ==== */'
here=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
inst=${1:-}

if [ -z "$inst" ] || [ ! -d "$inst/Browser" ]; then
	echo "usage: $0 <install-dir>        (the directory that contains Browser/)" >&2
	exit 2
fi
inst=$(CDPATH= cd -- "$inst" && pwd)

command -v zip >/dev/null || { echo "zip is not installed" >&2; exit 1; }
command -v unzip >/dev/null || { echo "unzip is not installed" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# patch <omni.ja> <entry> <stylesheet>...
#
# Pulls one entry out, cuts any block a previous run left, appends the given
# stylesheets under a marker, and puts the entry back.
patch() {
	jar=$1 entry=$2
	shift 2

	mkdir -p "$work/$(dirname "$entry")"
	unzip -p "$jar" "$entry" > "$work/$entry"
	[ -s "$work/$entry" ] || { echo "$jar has no $entry" >&2; exit 1; }

	# Our block is always last, so cutting at the marker restores the original.
	awk -v m="$MARK" 'index($0, m) == 1 { exit } { print }' \
		"$work/$entry" > "$work/base"
	mv "$work/base" "$work/$entry"

	{
		echo "$MARK"
		for css in "$@"; do
			echo ""
			cat "$here/$css"
		done
	} >> "$work/$entry"

	( cd "$work" && zip -X -q "$jar" "$entry" )
	echo "  $(basename "$(dirname "$jar")")/$(basename "$jar")  <-  $*"
}

# The design system -- the primitive colour tokens roughly five thousand
# var() references bottom out in. Panels, dialogs, notification bars and the
# in-content pages all follow from these.
patch "$inst/Browser/omni.ja" \
	chrome/toolkit/skin/classic/global/design-system/tokens-shared.css \
	theme/bbiwy-tokens.css

# The notification bars live in a shadow root, which the document's rules do not
# reach. Their own stylesheet is the only place they can be overridden.
patch "$inst/Browser/omni.ja" \
	chrome/toolkit/content/global/elements/infobar.css \
	theme/bbiwy-infobar.css

# The theme layer -- the toolbar, the tab strip and the address bar do not read
# the design system at all. They read their own variables, and this is where
# the route indicator goes too.
patch "$inst/Browser/browser/omni.ja" \
	chrome/browser/skin/classic/browser/browser-shared.css \
	theme/bbiwy-chrome.css theme/bbiwy-path.css

# Gecko keeps a parsed copy of what it read at startup. Left behind, it would
# serve the old stylesheets back and the change would look like it failed.
rm -rf "$inst/Browser/browser/startupCache" 2>/dev/null || true

echo "applied to $inst"
