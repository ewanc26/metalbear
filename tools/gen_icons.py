#!/usr/bin/env python3
"""Regenerate admin-mobile's icon PNGs from docs/logo.svg.

docs/logo.svg is the one bear. It is a set of axis-aligned <rect>s, so this
draws them directly with Pillow rather than needing an SVG renderer, and the
output does not depend on which rasteriser is installed. frontend/'s SVGs are
checked against the same rects by tools/check-drift.sh.

    python3 tools/gen_icons.py            # rewrite admin-mobile/assets/*.png
    python3 tools/gen_icons.py --check    # exit 1 if the PNG sizes are not as expected

Colour is the house logo green, #15803d, on white or transparent
(docs/house-style.md in wolfram: "never a new colour").
"""
import os
import re
import sys

from PIL import Image, ImageDraw

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SVG = os.path.join(ROOT, "docs", "logo.svg")
OUT = os.path.join(ROOT, "admin-mobile", "assets")
GREEN, WHITE = (0x15, 0x80, 0x3D, 255), (255, 255, 255, 255)

# file -> (size, background RGBA or None, bear colour, bear width as a fraction of the canvas)
# Adaptive-icon foreground/monochrome stay inside the 66% safe zone.
TARGETS = {
    "icon.png": (1024, WHITE, GREEN, 0.72),
    "splash-icon.png": (1024, None, GREEN, 0.60),
    "android-icon-foreground.png": (512, None, GREEN, 0.58),
    "android-icon-background.png": (512, WHITE, None, 0),
    "android-icon-monochrome.png": (432, None, GREEN, 0.58),
    "favicon.png": (48, WHITE, GREEN, 0.84),
}


def rects():
    svg = open(SVG).read()
    return [tuple(map(int, m)) for m in
            re.findall(r'<rect x="(-?\d+)" y="(-?\d+)" width="(\d+)" height="(\d+)"', svg)]


def render(size, bg, fg, frac, rs):
    img = Image.new("RGBA", (size, size), bg or (0, 0, 0, 0))
    if fg is None:
        return img
    vb = re.search(r'viewBox="0 0 (\d+) (\d+)"', open(SVG).read())
    w, h = int(vb.group(1)), int(vb.group(2))
    scale = size * frac / w
    ox, oy = (size - w * scale) / 2, (size - h * scale) / 2
    d = ImageDraw.Draw(img)
    for x, y, rw, rh in rs:
        d.rectangle([round(ox + x * scale), round(oy + y * scale),
                     round(ox + (x + rw) * scale) - 1, round(oy + (y + rh) * scale) - 1], fill=fg)
    return img


def main():
    rs = rects()
    if not rs:
        sys.exit("no rects found in docs/logo.svg")
    bad = 0
    for name, (size, bg, fg, frac) in TARGETS.items():
        path = os.path.join(OUT, name)
        if "--check" in sys.argv:
            if Image.open(path).size != (size, size):
                print(f"{name}: not {size}x{size}")
                bad = 1
            continue
        if size < 256:  # sub-pixel rects: draw large, then average down
            img = render(size * 10, bg, fg, frac, rs).resize((size, size), Image.LANCZOS)
        else:
            img = render(size, bg, fg, frac, rs)
        if bg is not None and name == "icon.png":
            img = img.convert("RGB")  # the store icon must be opaque
        img.save(path, optimize=True)
        print("wrote", name)
    sys.exit(bad)


main()
