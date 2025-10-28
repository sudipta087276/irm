def calculate_crc(data):
    # CRC-32 parameters
    polynomial = 0xEDB88320  # CRC-32 polynomial
    crc_init = 0xFFFFFFFF    # Initial CRC value

    # Initialize CRC
    crc = crc_init

    # Process each bit in the data
    for bit in data:
        crc = crc ^ bit  # XOR CRC with data bit
        for _ in range(8):
            if crc & 1:  # If least significant bit of CRC is 1
                crc = (crc >> 1) ^ polynomial  # Shift right and XOR polynomial
            else:
                crc = crc >> 1  # Shift right

    # Finalize CRC checksum
    crc_checksum = ~crc  # Take one's complement of CRC
    return crc_checksum