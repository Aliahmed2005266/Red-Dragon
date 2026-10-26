"""Generate the application icon.

Windows wants a multi-resolution .ico and Linux wants .png files, all rendered
from the same mark. This draws the mark procedurally so the repository does not
carry binary art that nobody can regenerate.

Run:  python scripts/make_icon.py
"""

import os
import struct
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.path.join(ROOT, "build")

BG = (10, 10, 10)          # near-black, matches the app background
RING = (0, 212, 255)       # the interface accent colour
GLOW = (255, 107, 107)     # the severity red used for critical findings


def blend(dst, src, alpha):
    return tuple(int(d + (s - d) * alpha) for d, s in zip(dst, src))


def render(size):
    """Return RGBA pixel rows for the mark at the given size."""
    cx = cy = (size - 1) / 2.0
    outer = size * 0.44
    ring = size * 0.34
    dot = size * 0.13

    rows = []
    for y in range(size):
        row = bytearray()
        for x in range(size):
            dx, dy = x - cx, y - cy
            dist = (dx * dx + dy * dy) ** 0.5

            # Anti-alias by how close the distance is to each radius
            def band(edge, width):
                return max(0.0, 1.0 - abs(dist - edge) / max(width, 1.0))

            a_ring = band(ring, size * 0.055)
            a_outer = band(outer, size * 0.02)
            a_dot = 1.0 if dist <= dot else 0.0
            a_dot *= max(0.0, 1.0 - max(0.0, dist - dot) / (size * 0.02))

            colour = BG
            colour = blend(colour, RING, a_outer * 0.55)
            colour = blend(colour, RING, a_ring)
            colour = blend(colour, GLOW, a_dot)

            alpha = int(255 * max(a_outer * 0.6, a_ring, a_dot))
            row += bytes((colour[0], colour[1], colour[2], alpha))
        rows.append(bytes(row))
    return rows


def write_png(path, rows, size):
    raw = b"".join(b"\x00" + r for r in rows)

    def chunk(tag, data):
        body = tag + data
        return (struct.pack(">I", len(data)) + body
                + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF))

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(raw, 9))
    png += chunk(b"IEND", b"")

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(png)
    return path


def write_ico(path, sizes):
    """Build a .ico containing BMP frames.

    NSIS is strict about icon files: it will not accept a PNG, and it
    historically rejects PNG-compressed frames inside an .ico. So every frame
    is written as a classic bottom-up DIB with an AND mask, which is what
    makensis expects.
    """
    blobs = [(size, ico_bmp_frame(render(size), size)) for size in sizes]

    header = struct.pack("<HHH", 0, 1, len(blobs))
    offset = 6 + 16 * len(blobs)

    entries = b""
    payload = b""
    for size, blob in blobs:
        # 0 means 256 in the ICO directory
        dim = 0 if size >= 256 else size
        entries += struct.pack(
            "<BBBBHHII", dim, dim, 0, 0, 1, 32, len(blob), offset)
        payload += blob
        offset += len(blob)

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(header + entries + payload)
    return path


def ico_bmp_frame(rows, size):
    """Encode RGBA rows as an ICO DIB: BITMAPINFOHEADER + XOR + AND mask."""
    header = struct.pack(
        "<IiiHHIIiiII",
        40,        # biSize
        size,      # biWidth
        size * 2,  # biHeight (XOR + AND stacked)
        1,         # biPlanes
        32,        # biBitCount
        0,         # biCompression
        0,         # biSizeImage
        0, 0, 0, 0,
    )

    # DIBs are stored bottom-up, and BGR rather than RGB
    xor = bytearray()
    for row in reversed(rows):
        for x in range(size):
            r, g, b, a = row[x * 4:x * 4 + 4]
            xor += bytes((b, g, r, a))

    # The AND mask is 1 bit per pixel, padded to 4-byte rows. Alpha carries the
    # real transparency, so the mask is all zeroes (nothing fully opaque-only).
    mask_row_bytes = ((size + 31) // 32) * 4
    mask = b"\x00" * (mask_row_bytes * size)

    return header + bytes(xor) + mask


def write_png_to_bytes(rows, size):
    raw = b"".join(b"\x00" + r for r in rows)

    def chunk(tag, data):
        body = tag + data
        return (struct.pack(">I", len(data)) + body
                + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF))

    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9))
            + chunk(b"IEND", b""))


def main():
    sizes = [16, 24, 32, 48, 64, 128, 256]

    cache = {}
    for s in sizes:
        cache[s] = render(s)

    made = []
    for s in (16, 32, 48, 64, 128, 256, 512):
        rows = cache.get(s) or render(s)
        made.append(write_png(os.path.join(BUILD, f"icon-{s}.png"), rows, s))

    # A single 512 png is what electron-builder picks up for the Linux targets
    made.append(write_png(os.path.join(BUILD, "icon.png"), render(512), 512))

    # Windows NSIS reads build/icon.ico
    made.append(write_ico(
        os.path.join(BUILD, "icon.ico"),
        [16, 24, 32, 48, 64, 128, 256]))

    for path in made:
        print(f"  {os.path.relpath(path, ROOT)}  ({os.path.getsize(path):,} bytes)")


if __name__ == "__main__":
    main()