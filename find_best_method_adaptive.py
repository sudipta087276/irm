import numpy as np

def find_best_method_adaptive(image_data, table_height, table_width, block_height, block_width):
    # Convert image data to float for calculations
    image_data = image_data.astype(float)
    watermark_data = np.zeros((table_height, table_width))
    
    for i in range(table_height):
        for j in range(table_width):
            # Extract 2x2 block
            a = np.array([
                image_data[i*block_height-1, j*block_width-1],
                image_data[i*block_height-1, j*block_width],
                image_data[i*block_height, j*block_width-1],
                image_data[i*block_height, j*block_width]
            ])
            
            # Calculate block min and max values
            block_values = np.floor(a/4) * 4
            block_max = np.max(block_values)
            block_min = np.min(block_values)
            
            # Calculate distances for each possible pixel value
            pixel_values = np.arange(block_min, block_max + 1, 4)
            if len(pixel_values) > 0:
                distances = np.array([
                    np.sum((pixel_val - a) ** 2)
                    for pixel_val in pixel_values
                ])
                
                # Find pixel value with minimum distance
                min_distance_idx = np.argmin(distances)
                watermark_data[i, j] = pixel_values[min_distance_idx]
    
    return watermark_data.astype(np.uint8)