# assets/

Master imagery for Tailshell. Every other reproduction of the mascot
across the repository (the UI bundle at
`ui/src/assets/images/`, future favicons, social cards) is a derived
copy that should trace back to these files.

| File | Size | Purpose |
| ---- | ---- | ------- |
| `Tailshell.png` | 1024×1024 | Master raster — the hermit-crab mascot. Use this whenever you need a high-resolution image (README hero, slides, blog posts). |
| `Tailshell.ico` | 16/32/48/64/128/256 | Multi-resolution Windows-style icon for any tooling that prefers `.ico` (favicons, GitHub repo, browser bookmarks). |
| `social-1024x512.png` | 1024×512 | GitHub social preview / OpenGraph card. Upload via **Settings → Social preview** on github.com. |
| `splash-screen.png` | 800×500 | Reserved for future UI splash screens. Same palette as the social card. |

The brand mark is currently shipped only as a raster (no SVG master).
If a vector version is added later, drop `Tailshell.svg` here and
re-export the raster sizes from it.

## Regenerating from the master PNG

```sh
# Multi-resolution ICO.
for s in 16 32 48 64 128 256; do
  magick assets/Tailshell.png -resize ${s}x${s} /tmp/tailshell-${s}.png
done
magick /tmp/tailshell-{16,32,48,64,128,256}.png assets/Tailshell.ico
rm /tmp/tailshell-*.png
```

## Where else the mascot lives

- `ui/src/assets/images/1024x1024.png` — bundled with the Vite build
  so the UI can render the mascot without hitting the network. Keep
  this in sync with `assets/Tailshell.png` (the UI copy is the
  derived asset).
- `nginx/favicon.svg` — the small monochrome favicon used by the
  login / invite / reset pages served by nginx. It is intentionally
  separate from the mascot.
