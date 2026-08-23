# Theme

The monochrome chrome, in two layers. Neither needs the browser recompiled.

## Why two files

Firefox's colours reach the screen by two separate routes, and a restyle has to
cover both.

**The design system.** About 130 primitive colour tokens are declared in
`toolkit/themes/shared/design-system/dist/tokens-shared.css`, and roughly 5,200
`var()` references across the themes bottom out in them. Panels, dialogs,
notification bars and the in-content pages all follow from those primitives.
`bbiwy-tokens.css` redefines them.

**The theme layer.** The toolbar, the tab strip and the address bar do not read
the design system. They read their own variables — `--toolbar-bgcolor`,
`--tab-selected-bgcolor`, `--toolbar-field-*` — declared directly in
`browser/themes/`. `bbiwy-chrome.css` sets those.

Overriding only the first leaves the toolbar untouched; that is measurable, and
it is also visible in a screenshot.

## The files

| File | Written by | Covers |
| --- | --- | --- |
| `bbiwy-tokens.css` | `tools/theme/graytokens.py` | the primitive colour tokens |
| `bbiwy-chrome.css` | by hand | toolbar, tabs, address bar, panels |

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

## Applying it

Both stylesheets are declared outside every `@layer`, which is what lets them
outrank the design system: an unlayered rule beats a layered one regardless of
order. Appending them to the end of the file they override is enough.

They ship inside `omni.ja`, which is an ordinary zip:

```sh
# the design system lives in the toolkit archive
unzip -p Browser/omni.ja chrome/toolkit/skin/classic/global/design-system/tokens-shared.css > t.css
cat theme/bbiwy-tokens.css >> t.css
zip -X Browser/omni.ja chrome/toolkit/skin/classic/global/design-system/tokens-shared.css

# the theme layer lives in the browser archive
unzip -p Browser/browser/omni.ja chrome/browser/skin/classic/browser/browser-shared.css > b.css
cat theme/bbiwy-chrome.css >> b.css
zip -X Browser/browser/omni.ja chrome/browser/skin/classic/browser/browser-shared.css
```

Replacing one entry measures at about 50 ms and leaves the other 8,600 intact.
The upstream build does the same thing to inject preferences, so this is the
supported shape of the archive rather than a trick played on it.

For a release build the same two files are applied to the source tree instead,
and the result is what a reproducible build reproduces. The repack is the design
loop, not the shipping mechanism.

## Not yet verified

The measurements and the generated token file are taken from the Firefox ESR
153 tree this browser is built from. The end-to-end repack was verified against
an ESR 140 build, where the toolbar, tabs, urlbar, panels and notification bars
all took the ink ramp. That build's design system is a much smaller file with no
chromatic primitives at all, so it exercises the mechanism but not the generated
token set. The token layer needs one pass on an ESR 153 build.
