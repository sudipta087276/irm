def smooth_function(original_pixel, lsb2, lsb1):
    # Convert to integer for bitwise operations
    original_pixel = int(original_pixel)
    
    # Set LSB1 (first bit)
    watermarked_pixel = original_pixel & ~1  # Clear first bit
    watermarked_pixel |= lsb1 & 1  # Set first bit to LSB1
    
    # Set LSB2 (second bit)
    watermarked_pixel &= ~2  # Clear second bit
    watermarked_pixel |= (lsb2 & 1) << 1  # Set second bit to LSB2
    
    return watermarked_pixel