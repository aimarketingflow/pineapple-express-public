#!/usr/bin/env python3
"""
StealthShark Icon Creator
Creates a simple icon for the StealthShark application
AIMF LLC - MobileShield Ecosystem
"""

from PIL import Image, ImageDraw, ImageFont
import os

def create_stealthshark_icon():
    """Create a simple StealthShark icon"""
    # Create a 512x512 image with transparent background
    size = 512
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Draw a circular background (dark blue/navy)
    circle_color = (25, 42, 86, 255)  # Navy blue
    draw.ellipse([20, 20, size-20, size-20], fill=circle_color)
    
    # Draw shark fin shape (simplified)
    fin_color = (255, 255, 255, 255)  # White
    fin_points = [
        (size//2, 80),      # Top point
        (size//2 - 60, 200), # Left point
        (size//2 + 60, 200), # Right point
    ]
    draw.polygon(fin_points, fill=fin_color)
    
    # Draw shield outline
    shield_color = (0, 255, 127, 255)  # Green
    shield_points = [
        (size//2, 250),      # Top center
        (size//2 - 80, 280), # Top left
        (size//2 - 80, 380), # Bottom left
        (size//2, 420),      # Bottom center
        (size//2 + 80, 380), # Bottom right
        (size//2 + 80, 280), # Top right
    ]
    draw.polygon(shield_points, outline=shield_color, width=8)
    
    # Add "SS" text in the center
    try:
        # Try to use a system font
        font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 120)
    except:
        # Fallback to default font
        font = ImageFont.load_default()
    
    text = "SS"
    bbox = draw.textbbox((0, 0), text, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]
    text_x = (size - text_width) // 2
    text_y = (size - text_height) // 2 + 20
    
    draw.text((text_x, text_y), text, fill=fin_color, font=font)
    
    # Save as PNG
    script_dir = os.path.dirname(os.path.abspath(__file__))
    icon_path = os.path.join(script_dir, "stealthshark-icon.png")
    img.save(icon_path, "PNG")
    print(f"✅ Icon created: {icon_path}")
    
    # Also create smaller versions
    for size_small in [256, 128, 64, 32, 16]:
        small_img = img.resize((size_small, size_small), Image.Resampling.LANCZOS)
        small_path = os.path.join(script_dir, f"stealthshark-icon-{size_small}.png")
        small_img.save(small_path, "PNG")
        print(f"✅ Icon created: {small_path}")

if __name__ == "__main__":
    try:
        create_stealthshark_icon()
        print("🦈 StealthShark icons created successfully!")
    except ImportError:
        print("⚠️ PIL (Pillow) not installed. Creating simple text-based icon...")
        # Create a simple text file as fallback
        icon_note_path = os.path.join(script_dir, "icon_note.txt")
        with open(icon_note_path, "w") as f:
            f.write("StealthShark Icon\n")
            f.write("To create a proper icon, install Pillow: pip3 install Pillow\n")
            f.write("Then run: python3 create_icon.py\n")
    except Exception as e:
        print(f"❌ Error creating icon: {e}")
