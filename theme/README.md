# Theme

The monochrome chrome and the route markings. Nothing here needs the browser
recompiled.

## Why four files

Colour reaches the screen by three separate routes, and a restyle has to cover
all three. A fourth file draws what the design adds rather than what it takes
away.

**The design system.** About 130 primitive colour tokens are declared in
`toolkit/themes/shared/design-system/dist/tokens-shared.css`, and roughly 5,200
`var()` references across the themes bottom out in them. Dialogs, icons and the
in-content pages all follow from those primitives. `bbiwy-tokens.css` redefines
them.

**The theme layer.** The toolbar, the tab strip and the address bar do not read
the design system. They read their own variables — `--toolbar-bgcolor`,
`--tab-selected-bgcolor`, `--toolbar-field-*` — declared directly in
`browser/themes/`. `bbiwy-chrome.css` sets those. Overriding only the design
system leaves the toolbar untouched; that is measurable, and it is also visible
in a screenshot.

**Shadow roots.** The notification bar is a custom element with a shadow root,
and a shadow root does not see the document's rules. Custom properties do cross
the boundary, but this component shadows the ones that would have carried the
ink ramp in. `bbiwy-infobar.css` is appended to the component's own stylesheet,
which is the only place it can be reached from.

**The route.** `bbiwy-path.css` draws what tells you which network path the
window is on: a glyph, the name in letters, and a treatment of the window edge.
See the table below.

| File | Written by | Covers |
| --- | --- | --- |
| `bbiwy-tokens.css` | `tools/theme/graytokens.py` | the primitive colour tokens |
| `bbiwy-chrome.css` | by hand | toolbar, tabs, address bar, panels |
| `bbiwy-infobar.css` | by hand | notification bars |
| `bbiwy-path.css` | by hand | the route marking |

`bbiwy-tokens.css` is generated, so regenerate it rather than editing it:

```sh
tools/theme/graytokens.py \
    <firefox>/toolkit/themes/shared/design-system/dist/tokens-shared.css \
    > theme/bbiwy-tokens.css
```

Each primitive becomes the grey of the same WCAG relative luminance, read off
the ink ramp in `docs/DESIGN-LANGUAGE.ko.md`. Matching luminance instead of
picking greys by eye preserves every contrast ratio upstream already tuned, so
no text silently falls below the threshold it was designed to meet.

Status keeps its colour. The status hues go grey as primitives — red used for
decoration is decoration — and the semantic tokens (`--icon-color-critical` and
its siblings) are then restored to the three signal colours explicitly. Colour
in this browser reports a state and nothing else.

## The route marking

Five preferences, one per path, and the stylesheet reads them directly:

```css
@media (-moz-pref("bbiwy.path.tor")) { … }
```

The launcher writes all five into the profile's `user.js` before starting the
browser — one true, four false. Writing only the true one is enough on a fresh
profile and wrong on a used one, because `prefs.js` keeps what was set before
and a leftover would leave a window claiming two routes at once.

A browser started outside the launcher has none of them set and is marked with
nothing, which is correct: it is on no BBIWY route and must not claim one.

The marks are the large variants of the shapes the design language names —
U+2B24 and U+25EF, not U+25CF and U+25CB. Side by side in a real window the
small pair draws at about half the height of the ring, the diamond and the
hexagon, and five marks that do not share a size read as five different kinds
of thing rather than five values of one.

## Applying it

```sh
tools/theme/apply.sh <install-dir>      # the directory holding Browser/
```

All four stylesheets are declared outside every `@layer`, which is what lets
them outrank the design system: an unlayered rule beats a layered one
regardless of order. Appending them to the end of the file they override is
enough.

They ship inside `omni.ja`, which is an ordinary zip. Replacing three entries
measures at **99 ms** and leaves the other eight thousand intact. The upstream
build does the same thing to inject preferences, so this is the supported shape
of the archive rather than a trick played on it. Running the script twice is
the same as running it once.

For a release build the same files are applied to the source tree instead, and
the result is what a reproducible build reproduces. The repack is the design
loop, not the shipping mechanism.

## Three traps, all found on a running browser

Every one of them fails **silently**. Nothing is logged, nothing throws, and
the browser looks fine — it just has no route marking, which is exactly the
state that means "daily".

1. **`-moz-bool-pref` no longer exists.** The spelling is now
   `-moz-pref("name")`. Gecko does not treat a media feature it has never heard
   of as an error; it skips the block.
2. **`urlbar-input-container` is a class, not an id.** The `#` form matches
   nothing at all.
3. **`outline` is not painted on the window element.** A 1px outline never
   reaches a pixel at any offset, while the identical rule on
   `#navigator-toolbox` draws. The window edge is a `border`.

## Not yet verified

The generated token file is taken from the Firefox ESR 153 tree this browser is
built from. The end-to-end repack was verified against an ESR 140 build, where
the toolbar, tabs, urlbar, panels, notification bars and all five route
markings came out as designed. The two trees declare the same token names, but
ESR 140 writes their values in `oklch()` where 153 writes hex, so the generated
set needs one pass on a 153 build.
