"""
Convert logo.png to logo.ico for Windows shortcuts
"""
from PIL import Image
import sys

def convert_png_to_ico():
    try:
        # Open PNG file
        img = Image.open('logo.png')
        
        # Resize to standard icon sizes
        icon_sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
        
        # Save as ICO with multiple sizes
        img.save('logo.ico', format='ICO', sizes=icon_sizes)
        
        print("[SUCCESS] Converted logo.png to logo.ico")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to convert: {e}")
        print("Please install Pillow: pip install Pillow")
        return False

if __name__ == "__main__":
    convert_png_to_ico()
