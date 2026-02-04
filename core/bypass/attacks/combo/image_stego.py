"""
Image Steganography Utilities

Functions for creating fake images with embedded steganographic data.
Supports PNG, JPEG, GIF formats with LSB embedding.
"""

import struct
import random
import os
from typing import Tuple, Optional


def _randbytes(n: int) -> bytes:
    """
    Compatibility helper for Python versions where random.randbytes may be unavailable.
    Falls back to os.urandom().
    """
    rb = getattr(random, "randbytes", None)
    if callable(rb):
        return rb(n)
    return os.urandom(n)


def embed_in_lsb(payload: bytes, pixel_count: Optional[int] = None) -> bytes:
    """
    Embed data in LSBs of fake pixel data.

    Args:
        payload: Data to embed
        pixel_count: Number of pixels (auto-calculated if None)

    Returns:
        Fake pixel data with embedded payload
    """
    if pixel_count is None:
        pixel_count = max(len(payload) * 8, 1000)

    fake_pixels = bytearray(_randbytes(pixel_count * 3))
    bit_index = 0

    for byte in payload:
        for bit_pos in range(8):
            if bit_index >= len(fake_pixels):
                break
            bit = (byte >> (7 - bit_pos)) & 1
            fake_pixels[bit_index] = (fake_pixels[bit_index] & 0xFE) | bit
            bit_index += 1

    return bytes(fake_pixels)


def create_fake_png_with_data(payload: bytes, method: str = "metadata") -> bytes:
    """
    Create fake PNG with embedded data.

    Args:
        payload: Data to embed
        method: Embedding method ('lsb' or 'metadata')

    Returns:
        PNG file bytes with embedded data
    """
    from .stego_utils import calculate_crc32

    png_signature = b"\x89PNG\r\n\x1a\n"
    width = 100
    height = 100
    bit_depth = 8
    color_type = 2  # RGB
    compression = 0
    filter_method = 0
    interlace = 0

    # IHDR chunk
    ihdr_data = struct.pack(
        ">IIBBBBB",
        width,
        height,
        bit_depth,
        color_type,
        compression,
        filter_method,
        interlace,
    )
    ihdr_crc = calculate_crc32(b"IHDR" + ihdr_data)
    ihdr_chunk = (
        struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + struct.pack(">I", ihdr_crc)
    )

    # Embed data based on method
    if method == "lsb":
        hidden_data = embed_in_lsb(payload)
    else:  # metadata or default
        hidden_data = payload

    # tEXt chunk with embedded data
    chunk_type = b"tEXt"
    chunk_data = b"comment\x00" + hidden_data
    chunk_crc = calculate_crc32(chunk_type + chunk_data)
    custom_chunk = (
        struct.pack(">I", len(chunk_data)) + chunk_type + chunk_data + struct.pack(">I", chunk_crc)
    )

    # IDAT chunk (fake compressed data)
    fake_image_data = b"\x78\x9c" + b"\x00" * 100
    idat_crc = calculate_crc32(b"IDAT" + fake_image_data)
    idat_chunk = (
        struct.pack(">I", len(fake_image_data))
        + b"IDAT"
        + fake_image_data
        + struct.pack(">I", idat_crc)
    )

    # IEND chunk
    iend_crc = calculate_crc32(b"IEND")
    iend_chunk = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", iend_crc)

    return png_signature + ihdr_chunk + custom_chunk + idat_chunk + iend_chunk


def create_fake_jpeg_with_data(payload: bytes, method: str = "comment") -> bytes:
    """
    Create fake JPEG with embedded data.

    Note:
        The 'method' parameter is intentionally unused. It is kept for backward
        compatibility and API stability. Data is always embedded in the JPEG
        comment segment.

    Args:
        payload: Data to embed in comment

    Returns:
        JPEG file bytes with embedded data
    """
    jpeg_signature = b"\xff\xd8\xff\xe0"
    jfif_header = b"\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00"

    # Comment segment (0xFFFE)
    comment_marker = b"\xff\xfe"
    comment_length = len(payload) + 2
    comment_segment = comment_marker + struct.pack(">H", comment_length) + payload

    # Fake SOF0 segment
    fake_data = b"\xff\xc0\x00\x11\x08\x00d\x00d\x01\x01\x11\x00\x02\x11\x01\x03\x11\x01"

    # End of Image
    eoi = b"\xff\xd9"

    return jpeg_signature + jfif_header + comment_segment + fake_data + eoi


def create_fake_gif_with_data(payload: bytes, method: str = "app_extension") -> bytes:
    """
    Create fake GIF with embedded data.

    Note:
        The 'method' parameter is intentionally unused. It is kept for backward
        compatibility and API stability. Data is always embedded in an application
        extension block.

    Args:
        payload: Data to embed (max 255 bytes in extension)

    Returns:
        GIF file bytes with embedded data
    """
    gif_signature = b"GIF89a"
    width = 100
    height = 100

    # Logical Screen Descriptor
    packed = 0x80  # Global color table flag
    bg_color = 0
    pixel_aspect = 0
    screen_descriptor = struct.pack("<HHBBB", width, height, packed, bg_color, pixel_aspect)

    # Global Color Table (256 colors * 3 bytes)
    color_table = b"\x00" * 768

    # Application Extension with embedded data (NETSCAPE2.0)
    app_extension = b"\x21\xff\x0bNETSCAPE2.0\x03\x01" + payload[:255] + b"\x00"

    # Image Descriptor
    image_separator = b"\x2c"
    left = 0
    top = 0
    img_width = 100
    img_height = 100
    packed_img = 0
    image_descriptor = image_separator + struct.pack(
        "<HHHHB", left, top, img_width, img_height, packed_img
    )

    # Image Data
    lzw_min_code_size = b"\x08"
    fake_image_data = b"\x02\x44\x01\x00"

    # Trailer
    trailer = b"\x3b"

    return (
        gif_signature
        + screen_descriptor
        + color_table
        + app_extension
        + image_descriptor
        + lzw_min_code_size
        + fake_image_data
        + trailer
    )


def create_image_http_response(image_data: bytes, image_format: str) -> bytes:
    """
    Create HTTP response containing an image.

    Args:
        image_data: Image file bytes
        image_format: Image format ('png', 'jpeg', 'gif')

    Returns:
        Complete HTTP response bytes
    """
    content_type = f"image/{image_format.lower()}"
    content_length = len(image_data)

    response = (
        f"HTTP/1.1 200 OK\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {content_length}\r\n"
        f"Cache-Control: public, max-age=3600\r\n"
        f"Server: Apache/2.4.41\r\n"
        f"\r\n"
    ).encode("utf-8") + image_data

    return response


def create_realistic_png_with_lsb(payload: bytes, width: int, height: int) -> bytes:
    """
    Create realistic PNG with LSB steganography.

    Args:
        payload: Data to embed
        width: Image width in pixels
        height: Image height in pixels

    Returns:
        PNG file bytes with LSB-embedded data
    """
    import zlib
    from .stego_utils import calculate_crc32

    png_signature = b"\x89PNG\r\n\x1a\n"

    # IHDR chunk
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    ihdr_crc = calculate_crc32(b"IHDR" + ihdr_data)
    ihdr_chunk = (
        struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + struct.pack(">I", ihdr_crc)
    )

    # Create RGB pixel data with LSB embedding
    pixel_data = create_rgb_pixels_with_lsb(payload, width, height)

    # Compress and create IDAT chunk
    compressed_data = zlib.compress(pixel_data)
    idat_crc = calculate_crc32(b"IDAT" + compressed_data)
    idat_chunk = (
        struct.pack(">I", len(compressed_data))
        + b"IDAT"
        + compressed_data
        + struct.pack(">I", idat_crc)
    )

    # IEND chunk
    iend_crc = calculate_crc32(b"IEND")
    iend_chunk = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", iend_crc)

    return png_signature + ihdr_chunk + idat_chunk + iend_chunk


def create_rgb_pixels_with_lsb(payload: bytes, width: int, height: int) -> bytes:
    """
    Create RGB pixel data with LSB-embedded payload.

    Args:
        payload: Data to embed
        width: Image width
        height: Image height

    Returns:
        Raw pixel data with filter bytes for PNG
    """
    pixels = bytearray()

    # Convert payload to bits
    payload_bits = []
    for byte in payload:
        for bit_pos in range(8):
            payload_bits.append((byte >> (7 - bit_pos)) & 1)

    bit_index = 0

    # Create scanlines with filter byte
    for y in range(height):
        pixels.append(0)  # Filter type: None

        for x in range(width):
            # Generate random RGB values
            r = random.randint(100, 200)
            g = random.randint(100, 200)
            b = random.randint(100, 200)

            # Embed bits in LSBs
            if bit_index < len(payload_bits):
                r = (r & 0xFE) | payload_bits[bit_index]
                bit_index += 1
            if bit_index < len(payload_bits):
                g = (g & 0xFE) | payload_bits[bit_index]
                bit_index += 1
            if bit_index < len(payload_bits):
                b = (b & 0xFE) | payload_bits[bit_index]
                bit_index += 1

            pixels.extend([r, g, b])

    return bytes(pixels)


def create_realistic_bmp_with_lsb(payload: bytes, width: int, height: int) -> bytes:
    """
    Create realistic BMP with LSB steganography.

    Args:
        payload: Data to embed
        width: Image width in pixels
        height: Image height in pixels

    Returns:
        BMP file bytes with LSB-embedded data
    """
    # BMP file header
    file_size = 54 + (width * height * 3)
    file_header = (
        b"BM"
        + struct.pack("<I", file_size)
        + b"\x00\x00\x00\x00"
        + struct.pack("<I", 54)  # Offset to pixel data
    )

    # BMP info header
    info_header = (
        struct.pack("<I", 40)  # Header size
        + struct.pack("<I", width)
        + struct.pack("<I", height)
        + struct.pack("<H", 1)  # Planes
        + struct.pack("<H", 24)  # Bits per pixel
        + b"\x00" * 24  # Compression and other fields
    )

    # Create pixel data with LSB embedding
    pixel_data = create_bmp_pixels_with_lsb(payload, width, height)

    return file_header + info_header + pixel_data


def create_bmp_pixels_with_lsb(payload: bytes, width: int, height: int) -> bytes:
    """
    Create BMP pixel data with LSB-embedded payload.

    Args:
        payload: Data to embed
        width: Image width
        height: Image height

    Returns:
        Raw pixel data in BMP format (BGR, bottom-up, row-padded)
    """
    pixels = bytearray()

    # Convert payload to bits
    payload_bits = []
    for byte in payload:
        for bit_pos in range(8):
            payload_bits.append((byte >> (7 - bit_pos)) & 1)

    bit_index = 0

    # BMP stores pixels bottom-up
    for y in range(height):
        row_data = bytearray()

        for x in range(width):
            # Generate random BGR values
            b = random.randint(100, 200)
            g = random.randint(100, 200)
            r = random.randint(100, 200)

            # Embed bits in LSBs
            if bit_index < len(payload_bits):
                b = (b & 0xFE) | payload_bits[bit_index]
                bit_index += 1
            if bit_index < len(payload_bits):
                g = (g & 0xFE) | payload_bits[bit_index]
                bit_index += 1
            if bit_index < len(payload_bits):
                r = (r & 0xFE) | payload_bits[bit_index]
                bit_index += 1

            row_data.extend([b, g, r])

        # Pad row to 4-byte boundary
        while len(row_data) % 4 != 0:
            row_data.append(0)

        pixels.extend(row_data)

    return bytes(pixels)


def calculate_image_capacity(image_size: Tuple[int, int]) -> int:
    """
    Calculate steganographic capacity of image in bytes.

    Args:
        image_size: (width, height) tuple

    Returns:
        Capacity in bytes (using LSB in RGB channels)
    """
    width, height = image_size
    total_pixels = width * height
    # 3 bits per pixel (R, G, B channels) = 3/8 bytes per pixel
    return (total_pixels * 3) // 8


def create_realistic_image_http_response(image_data: bytes, image_format: str) -> bytes:
    """
    Create realistic HTTP response for image with caching headers.

    Args:
        image_data: Image file bytes
        image_format: Image format ('png', 'bmp', etc.)

    Returns:
        Complete HTTP response bytes with realistic headers
    """
    from .stego_utils import calculate_crc32

    content_type = f"image/{image_format.lower()}"
    # Use stable checksum-based ETag instead of Python's hash(), which is randomized per process.
    etag = f'"{calculate_crc32(image_data):08x}"'

    response = (
        f"HTTP/1.1 200 OK\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(image_data)}\r\n"
        f"Cache-Control: public, max-age=31536000\r\n"
        f"ETag: {etag}\r\n"
        f"Last-Modified: Wed, 21 Oct 2023 07:28:00 GMT\r\n"
        f"Server: nginx/1.18.0\r\n"
        f"Accept-Ranges: bytes\r\n"
        f"\r\n"
    ).encode("utf-8") + image_data

    return response
