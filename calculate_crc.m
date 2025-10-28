function crc_checksum = calculate_crc(data)
    % CRC-32 parameters
    polynomial = uint32(hex2dec('EDB88320'));  % CRC-32 polynomial
    crc_init = uint32(hex2dec('FFFFFFFF'));    % Initial CRC value

    % Initialize CRC
    crc = crc_init;

    % Process each bit in the data
    for i = 1:numel(data)
        crc = bitxor(crc, uint32(data(i)));  % XOR CRC with data bit
        for j = 1:8
            if bitand(crc, uint32(1))  % If least significant bit of CRC is 1
                crc = bitxor(bitshift(crc, -1), polynomial);  % Shift right and XOR polynomial
            else
                crc = bitshift(crc, -1);  % Shift right
            end
        end
    end

    % Finalize CRC checksum
    crc_checksum = bitcmp(crc);  % Take one's complement of CRC
end