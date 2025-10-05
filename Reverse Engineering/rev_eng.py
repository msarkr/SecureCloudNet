# rev_eng.py
# make a BMP file with a hidden message in the pixel data

import struct
from pathlib import Path

# make an output folder for the bmp
out_dir = Path("samples")
out_dir.mkdir(exist_ok=True)
out_file = out_dir / "sample.bmp"

# helper: pack numbers in little endian
def le(fmt, *vals):
    return struct.pack("<" + fmt, *vals)

def make_bmp(path, w=64, h=16, secret=b"RE101{you_found_it}"):
    # bmp rows padded to 4 bytes
    row_bytes = (w * 3 + 3) & ~3
    pixel_bytes = row_bytes * h

    # file header
    bfType = b'BM'
    bfSize = 14 + 40 + pixel_bytes
    bfOffBits = 54  # pixel data starts here

    # dib header (BITMAPINFOHEADER)
    biSize = 40
    biPlanes = 1
    biBitCount = 24

    with open(path, "wb") as f:
        # write bmp file header
        f.write(bfType)
        f.write(le("I", bfSize))
        f.write(le("H", 0))  # reserved
        f.write(le("H", 0))
        f.write(le("I", bfOffBits))

        # write dib header
        f.write(le("I", biSize))
        f.write(le("i", w))
        f.write(le("i", h))
        f.write(le("H", biPlanes))
        f.write(le("H", biBitCount))
        f.write(le("I", 0))             # no compression
        f.write(le("I", pixel_bytes))   # size of raw data
        f.write(le("i", 2835))          # x ppm ~72 dpi
        f.write(le("i", 2835))          # y ppm ~72 dpi
        f.write(le("I", 0))             # clr used
        f.write(le("I", 0))             # clr important

        # pixel data
        buf = bytearray(pixel_bytes)
        buf[0:len(secret)] = secret     # put secret at start
        f.write(buf)

if __name__ == "__main__":
    make_bmp(out_file)
    print(f"made {out_file}, secret written at offset 0x36 (54)")
