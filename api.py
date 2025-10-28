from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import FileResponse
from pathlib import Path
import cv2
import numpy as np
import os
from get_logistic_sequence import get_logistic_sequence
from find_best_method_adaptive import find_best_method_adaptive
from smooth_function import smooth_function
from calculate_crc import calculate_crc

app = FastAPI(
    title="Image Recovery API",
    description="API for image watermarking, tampering detection, and recovery",
    version="1.0.0"
)

# Create necessary directories if they don't exist
for dir_name in ['Watermarked', 'Tampered', 'Recovered']:
    os.makedirs(os.path.join('data', dir_name), exist_ok=True)

@app.post("/watermark/")
async def watermark_image(
    image: UploadFile = File(...),
    block_height: int = 2,
    block_width: int = 2,
    initial_value: float = 0.3,
    logistic_parameter_a: float = 3.991
):
    """Watermark an input image using the specified parameters"""
    try:
        # Read and process the uploaded image
        contents = await image.read()
        nparr = np.frombuffer(contents, np.uint8)
        image512x512 = cv2.imdecode(nparr, cv2.IMREAD_GRAYSCALE)
        
        image_height, image_width = image512x512.shape
        table_height = image_height // block_height
        table_width = image_width // block_width

        # Generate logistic sequence
        logistic_sequence_output = get_logistic_sequence(initial_value, logistic_parameter_a, table_height, table_width)
        logistic_sequence_one = np.vstack((logistic_sequence_output, np.arange(table_height * table_width)))

        # Process image data
        image_data = image512x512[:table_height * block_height, :table_width * block_width]
        
        # Find best method adaptive
        pre_embed_recover_data = find_best_method_adaptive(image_data, table_height, table_width, block_height, block_width)
        pre_embed_recover_data_vector = np.vstack((pre_embed_recover_data.T.reshape(-1), np.arange(table_height * table_width)))

        # Initialize watermark map
        watermark_map_vector = np.zeros(table_height * table_width, dtype=np.uint8)
        number_of_pixel_bit = 8

        # Generate watermark map
        for i in range(table_height * table_width):
            pixel_value = pre_embed_recover_data_vector[0, logistic_sequence_one[0, i]]
            
            # Extract bits from pixel value
            bits = [(pixel_value >> k) & 1 for k in range(number_of_pixel_bit-1, number_of_pixel_bit-7, -1)]
            
            # Set high bits in watermark map
            for k, bit in enumerate(bits):
                watermark_map_vector[i] |= bit << (number_of_pixel_bit - k - 1)
            
            # Calculate CRC and authentication bits
            crc_checksum = calculate_crc(bits)
            authentication_data = crc_checksum % 4
            bit_p = (authentication_data >> 1) & 1
            bit_v = authentication_data & 1
            
            # Set authentication bits
            watermark_map_vector[i] = (watermark_map_vector[i] & ~3) | (bit_p << 1) | bit_v

        # Reshape watermark map
        watermark_map_matrix = watermark_map_vector.reshape(table_width, table_height).T

        # Initialize embedded image
        image_data_embed = np.zeros_like(image_data)

        # Embed watermark
        for i in range(table_height):
            for j in range(table_width):
                pixel_map = watermark_map_matrix[i, j]
                bits = [(pixel_map >> k) & 1 for k in range(7, -1, -1)]
                
                # Apply smooth function to each pixel in block
                pos = [(0, 0, 7, 6), (0, 1, 5, 4), (1, 0, 3, 2), (1, 1, 1, 0)]
                for di, dj, bi1, bi2 in pos:
                    y = i * block_height + di
                    x = j * block_width + dj
                    image_data_embed[y, x] = smooth_function(
                        image_data[y, x],
                        bits[bi1],
                        bits[bi2]
                    )

        # Calculate PSNR
        mse = np.mean((image_data - image_data_embed) ** 2)
        psnr = 10 * np.log10((255 * 255) / mse)

        # Save watermarked image
        output_filename = f'watermarked_{image.filename}'
        output_path = os.path.join('data', 'Watermarked', output_filename)
        cv2.imwrite(output_path, image_data_embed)

        return {
            "message": "Image watermarked successfully",
            "psnr": float(psnr),
            "watermarked_image": output_filename
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/watermarked/{filename}")
async def get_watermarked_image(filename: str):
    """Retrieve a watermarked image by filename"""
    file_path = os.path.join('data', 'Watermarked', filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Image not found")
    return FileResponse(file_path)

@app.get("/")
async def root():
    """Root endpoint that returns API information"""
    return {
        "message": "Welcome to Image Recovery API",
        "version": "1.0.0",
        "endpoints": [
            "/watermark/",
            "/watermarked/{filename}",
            "/"
        ]
    }