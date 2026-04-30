"""
Generate PNG icons from SVG for Chrome extension.
Requires: pip install pillow svglib
"""

import os
from svglib.svglib import svg2rlg
from reportlab.graphics import renderPM

# Read SVG
svg_path = os.path.join(os.path.dirname(__file__), 'icons', 'icon.svg')
icons_dir = os.path.join(os.path.dirname(__file__), 'icons')

# Generate PNG icons in required sizes
sizes = [16, 48, 128]

for size in sizes:
    output_path = os.path.join(icons_dir, f'icon{size}.png')
    drawing = svg2rlg(svg_path)
    renderPM.drawToFile(drawing, output_path, fmt='PNG', dpi=72)
    # Resize to exact dimensions
    from PIL import Image
    img = Image.open(output_path)
    img = img.resize((size, size), Image.Resampling.LANCZOS)
    img.save(output_path)
    print(f'Generated {output_path}')

print('Icon generation complete!')
print('You can now package the extension using package.bat or Chrome Extensions page.')
