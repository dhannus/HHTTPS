"""
Generate HHTTPS extension icons using only Python stdlib.
Creates minimal valid PNG files with the 👤 concept as colored circles.
"""
import struct, zlib, os

def make_png(size, bg_color, icon_color, state='neutral'):
    """Create a minimal PNG with a colored circle and human icon concept."""
    w = h = size

    # Create pixel data - RGBA
    pixels = []
    cx, cy = w // 2, h // 2
    r_outer = w // 2 - 1
    r_inner = w // 2 - 3

    for y in range(h):
        row = []
        for x in range(w):
            dx, dy = x - cx, y - cy
            dist = (dx*dx + dy*dy) ** 0.5

            if dist <= r_outer:
                if dist >= r_inner and size >= 32:
                    # Ring border
                    row.extend(icon_color + [255])
                else:
                    # Fill
                    row.extend(bg_color + [255])

                    # Draw simplified human figure (head + body)
                    if size >= 32:
                        head_r   = w * 0.15
                        head_cy  = cy - w * 0.12
                        body_top = cy - w * 0.01
                        body_bot = cy + w * 0.20
                        body_w   = w * 0.12

                        head_dist = ((x-cx)**2 + (y-head_cy)**2)**0.5
                        in_head   = head_dist <= head_r

                        in_body   = (abs(x-cx) <= body_w
                                     and body_top <= y <= body_bot)

                        if in_head or in_body:
                            row[-4:-1] = icon_color  # replace RGB, keep A
                    else:
                        # Tiny icon: just a dot
                        if (dx*dx + dy*dy) <= (w*0.2)**2:
                            row[-4:-1] = icon_color
            else:
                row.extend([0, 0, 0, 0])  # transparent

        pixels.append(bytes(row))

    # Build PNG
    def chunk(name, data):
        c = name + data
        return struct.pack('>I', len(data)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)

    ihdr_data = struct.pack('>IIBBBBB', w, h, 8, 6, 0, 0, 0)  # RGBA

    raw = b''
    for row in pixels:
        raw += b'\x00' + row  # filter type none

    idat_data = zlib.compress(raw, 9)

    png  = b'\x89PNG\r\n\x1a\n'
    png += chunk(b'IHDR', ihdr_data)
    png += chunk(b'IDAT', idat_data)
    png += chunk(b'IEND', b'')
    return png

# Icon states
configs = {
    'neutral':    ([7,  13, 24],    [0,  229, 255]),   # dark blue bg, cyan icon
    'verified':   ([4,  20, 10],    [0,  230, 118]),   # dark green bg, green icon
    'unverified': ([24, 7,  8],     [255, 82, 82]),    # dark red bg, red icon
    'supported':  ([24, 16, 4],     [255, 171, 64]),   # dark amber bg, amber icon
}

sizes = [16, 32, 48, 128]

os.makedirs('icons', exist_ok=True)

for size in sizes:
    # Default icon (cyan, neutral)
    bg, fg = configs['neutral']
    png_data = make_png(size, bg, fg, 'neutral')
    path = f'icons/icon{size}.png'
    with open(path, 'wb') as f:
        f.write(png_data)
    print(f'✓ {path} ({len(png_data)} bytes)')

# State-specific icons
for state, (bg, fg) in configs.items():
    for size in [32, 48]:
        png_data = make_png(size, bg, fg, state)
        path = f'icons/icon{size}_{state}.png'
        with open(path, 'wb') as f:
            f.write(png_data)
        print(f'✓ {path}')

print('\nAll icons generated.')
