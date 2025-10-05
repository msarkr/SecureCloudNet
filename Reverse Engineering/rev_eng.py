#!/usr/bin/env python3
# bmp_challenge.py
# Creates samples/sample.bmp (24-bit BMP) and embeds a short ASCII secret inside the image bytes.
# Line-by-line comments explain what each statement does.

import os                               # import the os module for filesystem operations
import struct                           # import struct to pack integers into little-endian bytes
from pathlib import Path                # import Path for convenient path handling

# OUT_DIR is a Path object pointing to the folder where we'll create the BMP.
OUT_DIR = Path("samples")

# mkdir(exist_ok=True) will create the directory if it doesn't exist; if it already exists, do nothing.
OUT_DIR.mkdir(exist_ok=True)

# OUT_FILE is the full path to the output BMP file (samples/sample.bmp).
OUT_FILE = OUT_DIR / "sample.bmp"

def pack_little(fmt, *vals):
    """
    Pack values using little-endian byte order.
    - fmt: struct format string (without the leading endianness char)
    - *vals: values to pack
    Returns the packed bytes.
    """
    return struct.pack("<" + fmt, *vals)  # '<' specifies little-endian; struct.pack returns bytes

def make_bmp_with_secret(path: Path, width=64, height=16, secret=b"RE101{hidden_flag}"):
    """
    Create a simple 24-bit BMP file and embed 'secret' bytes at the start of the pixel data.
    Parameters:
      path   : Path object where file will be written
      width  : image width in pixels
      height : image height in pixels
      secret : bytes to embed inside the pixel data (must be bytes, not str)
    """
    # Each pixel is 3 bytes for 24-bit BMP (B, G, R).
    # Each row of pixel data is padded to a 4-byte boundary.
    row_bytes = (width * 3 + 3) & ~3           # compute bytes per row including padding to 4-byte boundary

    # Total size of the pixel area = padded row size * number of rows
    pixel_data_size = row_bytes * height

    # === BMP File Header (14 bytes) ===
    bfType = b'BM'                             # 2 bytes: ASCII 'B' 'M' identifies BMP files
    bfSize = 14 + 40 + pixel_data_size         # 4 bytes: total file size (file header + DIB header + pixel data)
    bfReserved1 = 0                            # 2 bytes: reserved, set to 0
    bfReserved2 = 0                            # 2 bytes: reserved, set to 0
    bfOffBits = 14 + 40                        # 4 bytes: offset from file start to pixel data (file header + DIB header)

    # === DIB Header (BITMAPINFOHEADER, 40 bytes) ===
    biSize = 40                                # 4 bytes: size of this DIB header (40 bytes)
    biWidth = width                            # 4 bytes: image width in pixels (signed int)
    biHeight = height                          # 4 bytes: image height in pixels (signed int). Positive = bottom-up rows.
    biPlanes = 1                               # 2 bytes: number of color planes (must be 1)
    biBitCount = 24                            # 2 bytes: bits per pixel (24 = 3 bytes: B,G,R)
    biCompression = 0                          # 4 bytes: compression (0 = BI_RGB = no compression)
    biSizeImage = pixel_data_size              # 4 bytes: size of pixel data in bytes (may be 0 for uncompressed, but we set it)
    biXPelsPerMeter = 2835                     # 4 bytes: horizontal resolution (pixels per meter) ~72 DPI
    biYPelsPerMeter = 2835                     # 4 bytes: vertical resolution (pixels per meter)
    biClrUsed = 0                              # 4 bytes: number of palette colors used (0 = default)
    biClrImportant = 0                         # 4 bytes: number of important colors (0 = all important)

    # Open the output file in binary write mode
    with open(path, "wb") as f:
        # --- Write BMP File Header ---
        f.write(bfType)                           # write 'BM' (2 bytes)
        f.write(pack_little("I", bfSize))         # write 4-byte little-endian unsigned int (file size)
        f.write(pack_little("H", bfReserved1))    # write 2-byte little-endian unsigned short (reserved1)
        f.write(pack_little("H", bfReserved2))    # write 2-byte little-endian unsigned short (reserved2)
        f.write(pack_little("I", bfOffBits))      # write 4-byte little-endian unsigned int (offset to pixel data)

        # --- Write DIB Header (BITMAPINFOHEADER) ---
        f.write(pack_little("I", biSize))          # DIB header size
        f.write(pack_little("i", biWidth))         # width (signed int)
        f.write(pack_little("i", biHeight))        # height (signed int)
        f.write(pack_little("H", biPlanes))        # planes (unsigned short)
        f.write(pack_little("H", biBitCount))      # bits per pixel (unsigned short)
        f.write(pack_little("I", biCompression))   # compression (unsigned int)
        f.write(pack_little("I", biSizeImage))     # image size (unsigned int)
        f.write(pack_little("i", biXPelsPerMeter)) # X pixels per meter (signed int)
        f.write(pack_little("i", biYPelsPerMeter)) # Y pixels per meter (signed int)
        f.write(pack_little("I", biClrUsed))       # colors used (unsigned int)
        f.write(pack_little("I", biClrImportant))  # important colors (unsigned int)

        # --- Prepare pixel buffer and embed secret ---
        # Create a zero-filled bytearray of the exact pixel data size.
        pixel_buf = bytearray(pixel_data_size)

        # Place the secret bytes at the very start of the pixel data.
        # This writes the raw secret into the file's pixel area (not visible as text in image viewers).
        pixel_buf[0:len(secret)] = secret

        # Write the pixel buffer to the file (this completes the BMP)
        f.write(pixel_buf)

if __name__ == "__main__":
    # The secret must be bytes. If you prefer a different secret, edit the bytes here.
    secret = b"RE101{you_found_it}"  # <-- change this if you want a different hidden message

    # Create the BMP file with the secret embedded.
    # Default image size is width=64, height=16 (small and quick to generate)
    make_bmp_with_secret(OUT_FILE, width=64, height=16, secret=secret)

    # Print a short confirmation message to the console for the user
    print(f"Created {OUT_FILE} — secret embedded inside the file bytes.")
    print("Inspect the bytes with a hex editor, `xxd`, or `hexdump` to find the secret.")
