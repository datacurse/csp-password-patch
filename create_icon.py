from PIL import Image, ImageDraw

def create_icon():
    # Create a 256x256 image
    size = 256
    image = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    
    # Draw a simple lock icon
    # Lock body
    draw.rectangle([size//4, size//4, size*3//4, size*3//4], fill=(0, 120, 212))
    # Lock shackle
    draw.arc([size//4, size//8, size*3//4, size//2], 0, 180, fill=(0, 120, 212), width=size//16)
    
    # Save as ICO file
    image.save('icon.ico', format='ICO', sizes=[(256, 256)])

if __name__ == "__main__":
    create_icon()
