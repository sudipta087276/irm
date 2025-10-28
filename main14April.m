clc;        
clear;      
close all;  

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%Í¼ÏñË®Ó¡Ç¶Èë%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

relative_path = ['D:\image_recovery-master\.', filesep(), 'data', filesep()]; 
% load([relative_path, 'lena_gray_512']);
image512x512 = imread('D:\image_recovery-master\data\Cover\Baboon.tif');
% image512x512 = imread('D:\image_recovery-master\data\Jetplane_color.tiff');
[image_height, image_width] = size(image512x512);
block_height = 2;
block_width = 2;
table_height = image_height / block_height;
table_width = image_width / block_width;


% %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%logistic_sequence%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% [logistic_sequence_output] = get_logistic_sequence(0.3, 3.991, table_height, table_width);
% logistic_sequence_one = [logistic_sequence_output + 1; 1 : table_height * table_width];
% save('D:\image_recovery-master\data\logistic_sequence_one.mat', 'logistic_sequence_one');
load([relative_path, 'logistic_sequence_one.mat']);

image_data = image512x512(1 : table_height * block_height, 1 : table_width * block_width);
figure('NumberTitle', 'off', 'Name', 'Image Data'); 
% imshow(image_data);                          
% title('Image Data');

[pre_embed_recover_data] = find_best_method_adaptive(image_data, table_height, table_width, block_height, block_width);
pre_embed_recover_data_vector = [reshape(pre_embed_recover_data', 1, table_height * table_width); 1 : table_height * table_width];

pre_embed_recover_data_256 = zeros(table_height * block_height, table_width * block_width, 'uint8');
for i = 1 : table_height
    for j = 1 : table_width
        pre_embed_recover_data_256(i * block_height    , j * block_width) = pre_embed_recover_data(i, j);
        pre_embed_recover_data_256(i * block_height - 1, j * block_width) = pre_embed_recover_data(i, j);
        pre_embed_recover_data_256(i * block_height    , j * block_width - 1) = pre_embed_recover_data(i, j);
        pre_embed_recover_data_256(i * block_height - 1, j * block_width - 1) = pre_embed_recover_data(i, j);
    end
end

% % % [peak_snr, snr] = psnr(image_data, pre_embed_recover_data_256, 255);
% % % fprintf('\nThe Watermark Peak-SNR value is %0.4f', peak_snr);
% % % fprintf('\nThe SNR value is %0.4f \n', snr);

watermark_map_vector = zeros(1, table_height * table_width, 'uint8');
number_of_pixel_bit = 8;
% disp(bitget( pre_embed_recover_data_vector(1, logistic_sequence_one(1, 1) ), 7));
for i = 1 : table_height * table_width
% for i = 1 : 1
    for k = number_of_pixel_bit : - 1 : number_of_pixel_bit - 5
        watermark_map_vector(i) = bitset( watermark_map_vector(i), k, bitget( pre_embed_recover_data_vector(1, logistic_sequence_one(1, i) ), k) );
    end
    bit_b8 = bitget(watermark_map_vector(i), 8);
    bit_b7 = bitget(watermark_map_vector(i), 7);
    bit_b6 = bitget(watermark_map_vector(i), 6);
    bit_b5 = bitget(watermark_map_vector(i), 5);
    bit_b4 = bitget(watermark_map_vector(i), 4);
    bit_b3 = bitget(watermark_map_vector(i), 3);
    data= [bit_b8,bit_b7, bit_b6, bit_b5, bit_b4, bit_b3];

    crc_checksum = calculate_crc(data);
    % Create 2 bits for authentication from the extracted bits
    authentication_data = mod(crc_checksum, 4);
    auth = dec2bin(authentication_data, 2);
    bit_p = uint8(auth(1) - '0'); % Convert char to uint8
    bit_v = uint8(auth(2) - '0'); % Convert char to uint8

    watermark_map_vector(i) = bitset(watermark_map_vector(i), 2, bit_p);
    watermark_map_vector(i) = bitset(watermark_map_vector(i), 1, bit_v);   
end

watermark_map_matrix = reshape(watermark_map_vector, table_height, table_width)';
image_data_embed = zeros(table_height * block_height, table_width * block_width, 'uint8');
for i = 1 : 1 : table_height
    for j = 1 : 1 : table_width
        image_data_embed(1 + block_height * (i-1)    , 1 + block_width * (j - 1)    ) = smooth_function(image_data(1 + block_height * (i - 1)    , 1 + block_width * (j - 1)    ), bitget(watermark_map_matrix(i, j), 8), bitget(watermark_map_matrix(i, j), 7));
        image_data_embed(1 + block_height * (i-1)    , 1 + block_width * (j - 1) + 1) = smooth_function(image_data(1 + block_height * (i - 1)    , 1 + block_width * (j - 1) + 1), bitget(watermark_map_matrix(i, j),  6), bitget(watermark_map_matrix(i, j),  5));
        image_data_embed(1 + block_height * (i-1) + 1, 1 + block_width * (j-1)      ) = smooth_function(image_data(1 + block_height * (i - 1) + 1, 1 + block_width * (j - 1)    ), bitget(watermark_map_matrix(i, j),  4), bitget(watermark_map_matrix(i, j),  3));
        image_data_embed(1+block_height*(i-1)+1,1+block_width*(j-1)+1) = smooth_function(image_data(1+block_height*(i-1)+1,1+block_width*(j-1)+1),bitget(watermark_map_matrix(i,j),2),bitget(watermark_map_matrix(i,j),1));       
    end
end

dif=uint8(image_data-image_data_embed);
squared_error = dif.^2;
    MSE = mean(squared_error(:));
% MSE=sum(sum(dif).^2)/(512*512);
PSNR=10*log10((255*255)/MSE);
% fprintf('\nMSE:%7.2f',MSE);
fprintf('\nPSNR:%9.4f dB',PSNR);

% % % [peak_snr, snr] = psnr(image_data, image_data_embed, 255);
% % % fprintf('\nThe Embeded Image Peak-SNR value is %0.4f', peak_snr);
% % % % fprintf('\nThe SNR value is %0.4f \n', snr);
nc_value = normxcorr2(image_data, image_data_embed);
nc_value = max(nc_value(:));
fprintf('\nThe NC value is %0.4f \n', nc_value);

figure('NumberTitle', 'off', 'Name', 'Image Data Embeded');  
imshow(image_data_embed);   
imwrite(image_data_embed,'D:\image_recovery-master\data\Watermarked\Boat.gif','tif'); 
% title('Image Data Embeded');
image_data_E = image_data_embed;
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%Tampering%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
image_data_tampered = image_data_embed;
% % file_name='D:\image_recovery-master\data\Cover\eye1.tif'; %watermarked image
% % ob_image=imread(file_name);
% % ob_image=imresize(ob_image,[30 30]); 
% % ob_image=rgb2gray(ob_image);
% % file_name='D:\image_recovery-master\data\Cover\eye2.tif'; %watermarked image
% % ob_image1=imread(file_name);
% % ob_image1=rgb2gray(ob_image1);
% % ob_image1=imresize(ob_image1,[30 30]);
% % image_data_tampered(251:280, 261:290,:)= ob_image; 
% % image_data_tampered(251:280, 319:348,:)= ob_image1;

% file_name='D:\Matlab44\Image\face.tif'; %watermarked image
% ob_image10=imread(file_name);
% ob_image10=rgb2gray(ob_image10);
% ob_image10=imresize(ob_image10,[100 280]);
% image_data_tampered(45:144, 120:399,:)= ob_image10;

% file_name='D:\image_recovery-master\data\Cover\truck1.tiff'; %watermarked image
% ob_image3=imread(file_name);
% ob_image3=rgb2gray(ob_image3);
% ob_image3=imresize(ob_image3,[80 110]);
% image_data_tampered(161:240, 101:210,:)= ob_image3;
% image_data_tampered(261:340, 81:190,:)= ob_image3;


% file_name='D:\image_recovery-master\data\Cover\APC.tiff'; %watermarked image
% ob_image=imread(file_name);
% % ob_image=imresize(ob_image,[30 30]); 
% % ob_image=rgb2gray(ob_image);
% ob_image=imcrop(ob_image,[412 1 512 512]);
% imshow(ob_image);
% image_data_tampered( 1:512,412:512,:)= ob_image;

% file_name='D:\image_recovery-master\data\Cover\clock.jpg'; %watermarked image
% ob_image11=imread(file_name);
% ob_image11=rgb2gray(ob_image11);
% ob_image11=imresize(ob_image11,[100 80]);
% image_data_tampered(101:200, 331:410,:)= ob_image11;

% file_name='D:\image_recovery-master\data\Cover\boat.tif'; %watermarked image
% ob_image5=imread(file_name);
% ob_image5=rgb2gray(ob_image5);
% ob_image5=imresize(ob_image5,[70 50]);
% image_data_tampered(351:420, 181:230,:)= ob_image5;
% image_data_tampered(361:430, 241:290,:)= ob_image5;


% file_name='D:\image_recovery-master\data\Cover\lake.gif'; %watermarked image APC
% ob_image=imread(file_name);
% % ob_image=imresize(ob_image,[30 30]); 
% % ob_image=rgb2gray(ob_image);
% ob_image=imcrop(ob_image,[412 1 512-412 512-1]);
% image_data_tampered(1:512, 412:512,:)= ob_image;

% image_data_tampered(1:52 , 1:512)= 0;    %10 Upper
% image_data_tampered(1:103 , 1:512)= 0;    %20
% image_data_tampered(1:154 , 1:512)= 0;    %30
% image_data_tampered(1:205 , 1:512)= 0;    %40
%   image_data_tampered(1:256 , 1:512)= 0;  %50
% image_data_tampered(1:359 , 1:512)= 0;      %70

% image_data_tampered(1:512 , 1:52)= 0;    %10 leftside
% image_data_tampered(1:512 , 1:103)= 0;    %20
% image_data_tampered(1:512 , 1:154)= 0;    %30
% image_data_tampered(1:512 , 1:205)= 0;    %40
%   image_data_tampered(1:512 , 1:256)= 0;  %50
% image_data_tampered(1:512 , 1:359)= 0;      %70

% image_data_tampered(1:512 , 460:512)= 0;    %10 Rightside
% image_data_tampered(1:512 , 409:512)= 0;    %20
% image_data_tampered(1:512 , 358:512)= 0;    %30
% image_data_tampered(1:512 , 307:512)= 0;    %40
%   image_data_tampered(1:512 , 256:512)= 0;  %50
% image_data_tampered(1:512 , 153:512)= 0;      %70

% image_data_tampered(190:350 , 190:355)= 0;    %10 Center
% image_data_tampered(150:380 , 150:378)= 0;    %20
% image_data_tampered(120:400 , 120:400)= 0;    %30
% image_data_tampered(120:444 , 120:444)= 0;    %40
%   image_data_tampered(100:462 , 100:462)= 0;  %50
image_data_tampered(50:475 , 50:475)= 0;      %70


% image_data_tampered(250:300 , 350:450)= 100;    
% image_data_tampered(7:250  , 7:250)= 0;     
% image_data_tampered(3:252  , 3:252)= 0;     
% image_data_tampered(47:210 , 41:124) = 0;   
% image_data_tampered(47:210 , 133:216) = 0;  
% image_data_tampered(15:240   , 80:200) = 0;  

% load([relative_path, 'lena_collage_attack.mat']);
% image_data_tampered(47:210, 133:216) = image_data_tampered(47:210, 41:124); 
% lena_collage_attack = image_data_tampered(47:210,41:124);
% save('lena_collage_attack.mat','lena_collage_attack');
image_data_recovered = image_data_tampered;
figure('NumberTitle', 'off', 'Name', 'Image Data Tampered');	
imshow(image_data_tampered);                                  	
% title('Image Data Tampered');
imwrite(image_data_tampered,'D:\image_recovery-master\data\Tampered\Boboon70.tif','tif'); 

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% Tamper Detection %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

block_valid_or_invalid = ones(table_height, table_width, 'logical');
for i = 1 : 1 : table_height
    for j = 1 : 1 : table_width
        data1=0;
        bit_b8 = uint8(bitget(image_data_tampered(1 + block_height * (i - 1), 1 + block_width *(j - 1)), 2));
        bit_b7 = uint8(bitget(image_data_tampered(1 + block_height * (i - 1), 1 + block_width *(j - 1)), 1));
        bit_b6 = uint8(bitget(image_data_tampered(1 + block_height * (i - 1) , 1 + block_width * (j - 1)+ 1), 2));
        bit_b5 = uint8(bitget(image_data_tampered(1 + block_height * (i - 1) , 1 + block_width * (j - 1)+ 1), 1));
        bit_b4 = uint8(bitget(image_data_tampered(1 + block_height * (i - 1) + 1, 1 + block_width * (j - 1)), 2));
        bit_b3 = uint8(bitget(image_data_tampered(1 + block_height * (i - 1) + 1, 1 + block_width * (j - 1)), 1));
        
        bit_p1  = uint8(bitget(image_data_tampered(1 + block_height * (i - 1) + 1, 1 + block_width * (j - 1) + 1), 2));
        bit_v1  = uint8(bitget(image_data_tampered(1 + block_height * (i - 1) + 1, 1 + block_width * (j - 1) + 1), 1));
        data1= [bit_b8,bit_b7, bit_b6, bit_b5, bit_b4, bit_b3];
       
        crc_checksum1 = calculate_crc(data1);
    % Create 2 bits for authentication from the extracted bits
        authentication_data1 = mod(crc_checksum1, 4);
        auth1 = dec2bin(authentication_data1, 2);
    	bit_p11 = uint8(auth1(1) - '0'); % Convert char to uint8
        bit_v11 = uint8(auth1(2) - '0');
% %         bit_p_calculate = xor(xor(xor(xor(xor(bit_b8, bit_b7), bit_b6), bit_b5), bit_b4), bit_b3);
        block_index = (i - 1) * table_width + j;
        if (bit_p1 == bit_p11) && (bit_v1 == bit_v11)
            block_valid_or_invalid(i, j) = 1;
        else
            block_valid_or_invalid(i, j) = 0;
        end
    end
end


block_valid_or_invalid_backup = block_valid_or_invalid;
block_valid_or_invalid_1 = block_valid_or_invalid;


% for i = 1 : 1 : table_height
%     for j = 1 : 1 : table_width
%         if block_valid_or_invalid(i, j) == 1
%             if i == 1 && j == 1 
%                 %(E,SE,S)
%                 if (block_valid_or_invalid(i + 1, j) == 0 && block_valid_or_invalid(i + 1, j + 1) == 0 && block_valid_or_invalid(i, j + 1) == 0)
%                     block_valid_or_invalid_backup(i, j) = 0;
%                 end
%             elseif i == 1 && j == table_width
%                 %(W,SW,S)
%                 if (block_valid_or_invalid(i + 1, j) == 0 && block_valid_or_invalid(i + 1, j - 1) == 0 && block_valid_or_invalid(i, j - 1) == 0)
%                     block_valid_or_invalid_backup(i, j) = 0;
%                 end
%             elseif i == table_height && j == table_width
%                 %(W,NW,N)
%                 if (block_valid_or_invalid(i - 1, j) == 0 && block_valid_or_invalid(i - 1, j - 1) == 0 && block_valid_or_invalid(i, j - 1) == 0)
%                     block_valid_or_invalid_backup(i, j) = 0;
%                 end
%             elseif i == table_height && j == 1
%                 %(N,NE,E)
%                 if (block_valid_or_invalid(i - 1, j) == 0 && block_valid_or_invalid(i - 1, j + 1) == 0 && block_valid_or_invalid(i, j + 1) == 0)
%                     block_valid_or_invalid_backup(i, j) = 0;
%                 end
%             elseif i > 1 && i < table_height && j == 1
%                 %(N,NE,E)(E,SE,S)
%                 if  (block_valid_or_invalid(i - 1, j) == 0 && block_valid_or_invalid(i - 1, j + 1) == 0  && block_valid_or_invalid(i, j + 1) == 0) || (block_valid_or_invalid(i + 1, j) == 0 && block_valid_or_invalid(i + 1, j + 1) == 0 && block_valid_or_invalid(i, j + 1) == 0)
%                     block_valid_or_invalid_backup(i, j) = 0;
%                 end
%             elseif i == 1 && j > 1 && j < table_width
%                 %(E,SE,S)(W,SW,S)
%                 if  (block_valid_or_invalid(i + 1, j) == 0 && block_valid_or_invalid(i + 1, j + 1) == 0 && block_valid_or_invalid(i, j + 1) == 0 )||(block_valid_or_invalid(i + 1, j) == 0 && block_valid_or_invalid(i + 1, j - 1) == 0 && block_valid_or_invalid(i, j - 1) == 0)
%                     block_valid_or_invalid_backup(i,j) = 0;
%                 end
%             elseif i > 1 && i < table_height && j == table_width
%                 %(W,NW,N)(W,SW,S)
%                 if (block_valid_or_invalid(i - 1, j)==0 && block_valid_or_invalid(i - 1, j - 1) == 0 && block_valid_or_invalid(i, j - 1) == 0) || (block_valid_or_invalid(i + 1, j) == 0 && block_valid_or_invalid(i + 1, j - 1) == 0 && block_valid_or_invalid(i, j - 1) == 0)
%                     block_valid_or_invalid_backup(i, j) = 0;
%                 end
%             elseif i == table_height && j > 1 && j < table_width
%                 %(W,NW,N)(N,NE,E)
%                 if (block_valid_or_invalid(i - 1, j) == 0 && block_valid_or_invalid(i - 1, j - 1) == 0 && block_valid_or_invalid(i, j - 1) == 0) || (block_valid_or_invalid(i - 1, j) == 0 && block_valid_or_invalid(i - 1, j + 1) == 0 && block_valid_or_invalid(i, j + 1) == 0)
%                     block_valid_or_invalid_backup(i, j) = 0;
%                 end
%             else
%                 %(W,NW,N)(N,NE,E)(E,SE,S)(W,SW,S)
%                 if (block_valid_or_invalid(i - 1, j) == 0 && block_valid_or_invalid(i - 1, j - 1) == 0 && block_valid_or_invalid(i, j - 1) == 0) || (block_valid_or_invalid(i - 1, j) == 0 && block_valid_or_invalid(i - 1, j + 1) == 0 && block_valid_or_invalid(i, j + 1) == 0) || (block_valid_or_invalid(i + 1, j) == 0 && block_valid_or_invalid(i + 1, j + 1) == 0 && block_valid_or_invalid(i, j + 1) == 0 ) || (block_valid_or_invalid(i + 1, j) == 0 && block_valid_or_invalid(i + 1, j - 1) == 0 && block_valid_or_invalid(i, j - 1) == 0)
%                     block_valid_or_invalid_backup(i, j) = 0;
%                 end
%             end   
%         end
%     end
% end

% block_valid_or_invalid = block_valid_or_invalid_backup;
block_invalid_count = 0;

image_valid_or_invalid = zeros(table_height * block_height,table_width * block_width);
for i = 1 : table_height    
    for j = 1 : table_width
        if block_valid_or_invalid_1(i, j) == 0
            for i_to_configure = ((i - 1) * block_height + 1) : 1 : i * block_height  
                for j_to_configure = ((j - 1) * block_width + 1) : 1 : j * block_width
                    image_valid_or_invalid(i_to_configure, j_to_configure) = 0;
                end
            end
        elseif block_valid_or_invalid_1(i, j) == 1
            for i_to_configure = ((i - 1) * block_height + 1) : 1 : i * block_height  
                for j_to_configure = ((j - 1) * block_width + 1): 1 : j * block_width
                    image_valid_or_invalid(i_to_configure, j_to_configure) = 1;
                end
            end
        end
    end
end

invaild_count = 0;
for i = 1 : table_height * block_height    
    for j = 1 : table_width * block_width
        if (image_valid_or_invalid(i, j)~=1)
            invaild_count = invaild_count + 1;
        end
    end
end
tampered_percentage = invaild_count * 100 / (table_height * block_height * table_width * block_width);
fprintf('The percentage of tampered is %0.4f%%\n', tampered_percentage);

image_valid_or_invalid_standard = zeros(table_height * block_height, table_width * block_width, 'uint8');
for i = 1 : table_height * block_height    
    for j = 1 : table_width * block_width
        if (image_valid_or_invalid(i, j)==1)
            image_valid_or_invalid_standard(i, j) = 0;
        else
            image_valid_or_invalid_standard(i, j) = 255;
        end
    end
end
figure('NumberTitle', 'off', 'Name', 'Image Data Standard');  
imshow(image_valid_or_invalid_standard);                          
% title('Image Data Recovered');
imwrite(image_valid_or_invalid_standard,'D:\image_recovery-master\data\DETampered\Boboon70.tif','tif');
watermark_recover = zeros(1, table_height * table_width, 'uint16');
for i = 1 : table_height * table_width
%     for i = 1 : 1
    bit_8_3_get = 0;
    find_index = find(logistic_sequence_one(1, :)==i);   
    block_row = floor(find_index / table_width) + 1;
    block_col = mod(find_index, table_width);
    if block_col == 0
       block_row = block_row - 1;
       block_col = table_width;
    end
    if block_valid_or_invalid_1(block_row, block_col) == 1
        bit_8_3_get = 1;
        bit_8 = bitget(image_data_tampered(block_row * block_height - 1, block_col * block_width - 1), 2);
        bit_7 = bitget(image_data_tampered(block_row * block_height - 1, block_col * block_width - 1), 1);
        bit_6 = bitget(image_data_tampered(block_row * block_height - 1, block_col * block_width ), 2);
        bit_5 = bitget(image_data_tampered(block_row * block_height - 1, block_col * block_width ), 1);
        bit_4 = bitget(image_data_tampered(block_row * block_height, block_col * block_width-1), 2);
        bit_3 = bitget(image_data_tampered(block_row * block_height , block_col * block_width-1), 1);
    end
    
    if bit_8_3_get == 1
        watermark_recover(i) =  128 * bit_8 + 64 * bit_7 + 32 * bit_6 + 16 * bit_5 + 8 * bit_4 + 4 * bit_3 ;
         bit_8 = 0;bit_7 = 0; bit_6 = 0; bit_5 = 0; bit_4 = 0; bit_3 = 0;
    else
        watermark_recover(i) = 9999;
        bit_8 = 0;bit_7 = 0; bit_6 = 0; bit_5 = 0; bit_4 = 0; bit_3 = 0;        
    end
end
watermark_recover_matrix = reshape(watermark_recover, table_height, table_width)';
% imshow(watermark_recover_matrix);

block_valid_or_invalid_backup = block_valid_or_invalid_1;
block_valid_or_invalid_backup_1 = block_valid_or_invalid_1;
for i = 1 : table_height    
    for j = 1 : table_width
        if block_valid_or_invalid_1(i, j) == 0 && watermark_recover_matrix(i, j) ~= 9999
            image_data_recovered(1 + block_height * (i - 1)  , 1 + block_width * (j - 1)  ) = watermark_recover_matrix(i,j);
            image_data_recovered(1 + block_height * (i - 1)  , 1 + block_width * (j - 1)+1) = watermark_recover_matrix(i,j);
            image_data_recovered(1 + block_height * (i - 1)+1, 1 + block_width * (j - 1)  ) = watermark_recover_matrix(i,j);
            image_data_recovered(1 + block_height * (i - 1)+1, 1 + block_width * (j - 1)+1) = watermark_recover_matrix(i,j);
            block_valid_or_invalid_backup(i, j)=1;
            block_valid_or_invalid_1(i, j)=1;
         end
           
    end
end

block_equal_zero = 0;
for i = 1 : 1 : table_height
    for j = 1 : 1 : table_width
        if block_valid_or_invalid_backup(i, j) == 0
            block_equal_zero = block_equal_zero + 1;
        end
    end
end

fprintf('The percentage of blocks not recovered after stage-1 tamper recovery is %0.4f%%\n', (block_equal_zero * 100) / (table_width * table_height));
NoofBlock = (512*512)/(2*2);
x=1;
y=1;
p=1;
q=1;
% for (kk = 1:NoofBlock)
% for (kk = 1:10)
figure('NumberTitle', 'off', 'Name', 'Image Data Recovered pre');  
imshow(image_data_recovered);  
    avg_matrix= zeros(256,256);
for i = 1:256
    for j = 1:256
        
        % Calculate the average of the block
        block=image_data_recovered(y:y+(2-1),x:x+(2-1));
        avg_value = round(mean2(block(:)));
%         avg_value = image_data_recovered(1 + block_height * (i - 1)  , 1 + block_width * (j - 1)  ) +  image_data_recovered(1 + block_height * (i - 1)  , 1 + block_width * (j - 1)+1)  + image_data_recovered(1 + block_height * (i - 1)+1, 1 + block_width * (j - 1)  ) +  image_data_recovered(1 + block_height * (i - 1)+1, 1 + block_width * (j - 1)+1)
          avg_matrix(i, j) = avg_value;
        
    if (x+2) >= 512
        x=1;
        y=y+2;
    else
        x=x+2;
    end
    end
end

rate = 1.5;
for i = 1 : 1 : table_height
    for j = 1 : 1 : table_width
       flag =0;
        if block_valid_or_invalid_1(i, j) == 0   
%          if(i<=128) && (J<=128)
            if (i > 1) && (i < table_height) && (j > 1) && (j < table_width)% 1
                % N1
                sum=0;
                valid_count=0;
                rec=0;
                if block_valid_or_invalid_1(i - 1, j - 1) == 1 && avg_matrix(i - 1, j - 1) ~= 0
%                     sum=sum+ avg_matrix(1 + block_height * (i - 1)  , 1 + block_width * (j - 1)  );
                      sum=sum+ avg_matrix((i - 1),(j - 1));
                      valid_count=valid_count+1;
                end
                % N2
                if block_valid_or_invalid_1(i-1,j) == 1 && avg_matrix(i - 1, j) ~= 0
%                   sum=sum+ avg_matrix(1 + block_height * (i - 1)  , 1 + block_width * (j)  );
                    sum=sum+ avg_matrix((i - 1),(j));
                    valid_count=valid_count+1;
                end
                % N3
                if block_valid_or_invalid_1(i-1,j+1) == 1 && avg_matrix(i - 1, j + 1) ~= 0
%                   sum=sum+ avg_matrix(1 + block_height * (i - 1)  , 1 + block_width * (j+1)  );
                    sum=sum+ avg_matrix((i - 1),(j + 1));
                    valid_count=valid_count+1;
                   
                end                
                % N4
                if block_valid_or_invalid_1(i,j+1) == 1 && avg_matrix(i , j + 1) ~= 0
%                     sum=sum+ avg_matrix(1 + block_height * (i)  , 1 + block_width * (j+1)  );
                      sum=sum+ avg_matrix((i),(j + 1));
                      valid_count=valid_count+1;
                    
                end
                % N5
                if block_valid_or_invalid_1(i+1,j+1) == 1 && avg_matrix(i + 1, j + 1) ~= 0
%                     sum=sum+ avg_matrix(1 + block_height * (i + 1)  , 1 + block_width * (j+1)  );
                      sum=sum+ avg_matrix((i + 1),(j + 1));
                      valid_count=valid_count+1;

                end
                % N6
                if block_valid_or_invalid_1(i+1,j) == 1 && avg_matrix(i + 1, j ) ~= 0
%                   sum=sum+ avg_matrix(1 + block_height * (i + 1)  , 1 + block_width * (j)  );
                    sum=sum+ avg_matrix((i + 1),(j));
                    valid_count=valid_count+1;
                end
                % N7
                if block_valid_or_invalid_1(i+1,j-1) == 1 && avg_matrix(i + 1, j - 1) ~= 0
%                   sum=sum+ avg_matrix(1 + block_height * (i + 1)  , 1 + block_width * (j-1)  );
                    sum=sum+ avg_matrix((i + 1),(j - 1));
                    valid_count=valid_count+1;
                  
                end
                % N8
                if block_valid_or_invalid_1(i,j-1) == 1 && avg_matrix(i, j - 1) ~= 0

%                   sum=sum+ avg_matrix(1 + block_height * (i)  , 1 + block_width * (j-1)  );
                    sum=sum+ avg_matrix((i),(j - 1));
                    valid_count=valid_count+1;
                end 
            rec = round(sum/valid_count);
            image_data_recovered(1+block_height*(i-1),1+block_width*(j-1)) = rec;
            image_data_recovered(1+block_height*(i-1)+1,1+block_width*(j-1)) = rec;
            image_data_recovered(1+block_height*(i-1),1+block_width*(j-1)+1) = rec;
            image_data_recovered(1+block_height*(i-1)+1,1+block_width*(j-1)+1) = rec;
            flag =1;
%             block_valid_or_invalid_1(i,j) = 1;
            elseif (i > 1) && (i < table_height) && (j==1)% 2
                % N2
                sum=0;
                valid_count=0;
                rec=0;
                if block_valid_or_invalid_1(i-1,j) == 1 && avg_matrix(i - 1, j) ~= 0
%                         sum=sum+ avg_matrix(1 + block_height * (i - 1)  , 1 + block_width * (j)  );
                        sum=sum+ avg_matrix((i - 1),(j));
                        valid_count=valid_count+1;
                end
                % N3
                if block_valid_or_invalid_1(i-1,j+1) == 1 && avg_matrix(i - 1, j + 1) ~= 0
%                     sum=sum+ avg_matrix(1 + block_height * (i - 1)  , 1 + block_width * (j+1)  );
                       sum=sum+ avg_matrix((i - 1),(j+1));
                        valid_count=valid_count+1;
                end                
                % N4
                if block_valid_or_invalid_1(i,j+1) == 1 && avg_matrix(i, j + 1) ~= 0
%                         sum=sum+ avg_matrix(1 + block_height * (i )  , 1 + block_width * (j+1)  );
                        sum=sum+ avg_matrix((i),(j+1));
                        valid_count=valid_count+1;
                end
                % N5
                if block_valid_or_invalid_1(i+1,j+1) == 1 && avg_matrix(i+ 1, j + 1) ~= 0

%                         sum=sum+ avg_matrix(1 + block_height * (i + 1)  , 1 + block_width * (j+1)  );
                        sum=sum+ avg_matrix((i + 1),(j+1));
                        valid_count=valid_count+1;
                end
                % N6
                if block_valid_or_invalid_1(i+1,j) == 1 && avg_matrix(i + 1, j) ~= 0
%                         sum=sum+ avg_matrix(1 + block_height * (i + 1)  , 1 + block_width * (j)  );
                        sum=sum+ avg_matrix((i + 1),(j));
                        valid_count=valid_count+1;
                     
                end
                rec= round(sum/valid_count);
            image_data_recovered(1+block_height*(i-1),1+block_width*(j-1)) = rec;
            image_data_recovered(1+block_height*(i-1)+1,1+block_width*(j-1)) = rec;
            image_data_recovered(1+block_height*(i-1),1+block_width*(j-1)+1) = rec;
            image_data_recovered(1+block_height*(i-1)+1,1+block_width*(j-1)+1) = rec;
            flag =1;
%             block_valid_or_invalid_1(i,j) = 1
            elseif (i > 1) && (i < table_height) && (j==table_width)% 3
                % N1
                    sum=0;
                    valid_count=0;
                    rec=0;
                if block_valid_or_invalid_1(i-1,j-1) == 1 && avg_matrix(i - 1, j - 1) ~= 0
%                     sum=sum+ avg_matrix(1 + block_height * (i - 1)  , 1 + block_width * (j-1)  );
                    sum=sum+ avg_matrix((i - 1), (j-1));
                        valid_count=valid_count+1;
                end
                % N2
                if block_valid_or_invalid_1(i-1,j) == 1 && avg_matrix(i - 1, j) ~= 0
%                     sum=sum+ avg_matrix(1 + block_height * (i - 1)  , 1 + block_width * (j)  );
                     sum=sum+ avg_matrix((i - 1), (j));
                        valid_count=valid_count+1;
                end
                % N6
                if block_valid_or_invalid_1(i+1,j) == 1 && avg_matrix(i + 1, j ) ~= 0
%                      sum=sum+ avg_matrix(1 + block_height * (i + 1)  , 1 + block_width * (j)  );
                      sum=sum+ avg_matrix((i + 1), (j));
                        valid_count=valid_count+1;
                end
                % N7
                if block_valid_or_invalid_1(i+1,j-1) == 1 && avg_matrix(i+ 1, j - 1) ~= 0
%                      sum=sum+ avg_matrix(1 + block_height * (i + 1)  , 1 + block_width * (j-1)  );
                      sum=sum+ avg_matrix((i + 1), (j-1));
                        valid_count=valid_count+1;
                end
                % N8
                if block_valid_or_invalid_1(i,j-1) == 1 && avg_matrix(i, j - 1) ~= 0
%                      sum=sum+ avg_matrix(1 + block_height * (i)  , 1 + block_width * (j-1)  );
                      sum=sum+ avg_matrix((i ), (j-1));
                        valid_count=valid_count+1;
                          
                end
                
                rec= round(sum/valid_count);
            image_data_recovered(1+block_height*(i-1),1+block_width*(j-1)) = rec;
            image_data_recovered(1+block_height*(i-1)+1,1+block_width*(j-1)) = rec;
            image_data_recovered(1+block_height*(i-1),1+block_width*(j-1)+1) = rec;
            image_data_recovered(1+block_height*(i-1)+1,1+block_width*(j-1)+1) = rec;
%             block_valid_or_invalid_1(i,j) = 1;
                flag =1;
            elseif (i==1)&& (j > 1) && (j < table_width)% 4              
                        sum=0;
                        valid_count=0;
                        rec=0;
                if block_valid_or_invalid_1(i,j+1) == 1
%                     sum=sum+ avg_matrix(1 + block_height * (i)  , 1 + block_width * (j+1)  );
                    sum=sum+ avg_matrix((i), (j+1));
                        valid_count=valid_count+1;
                end
                % N5
                if block_valid_or_invalid_1(i+1,j+1) == 1
%                    sum=sum+ avg_matrix(1 + block_height * (i+1)  , 1 + block_width * (j+1)  );
                   sum=sum+ avg_matrix((i+1), (j+1));
                        valid_count=valid_count+1;
                end
                % N6
                if block_valid_or_invalid_1(i+1,j) == 1
%                     sum=sum+ avg_matrix(1 + block_height * (i+1)  , 1 + block_width * (j)  );
                        sum=sum+ avg_matrix((i+1), (j));
                        valid_count=valid_count+1;
                end
                % N7
                if block_valid_or_invalid_1(i+1,j-1) == 1
%                     sum=sum+ avg_matrix(1 + block_height * (i+1)  , 1 + block_width * (j-1)  );
                    sum=sum+ avg_matrix((i+1), (j-1));
                        valid_count=valid_count+1;
                end
                % N8
                if block_valid_or_invalid_1(i,j-1) == 1
%                     sum=sum+ avg_matrix(1 + block_height * (i)  , 1 + block_width * (j-1)  );
                    sum=sum+ avg_matrix((i), (j-1));
                        valid_count=valid_count+1;
                end 
                rec= round(sum/valid_count);
            image_data_recovered(1+block_height*(i-1),1+block_width*(j-1)) = rec;
            image_data_recovered(1+block_height*(i-1)+1,1+block_width*(j-1)) = rec;
            image_data_recovered(1+block_height*(i-1),1+block_width*(j-1)+1) = rec;
            image_data_recovered(1+block_height*(i-1)+1,1+block_width*(j-1)+1) = rec; 
            flag =1;
%             block_valid_or_invalid_1(i,j) = 1;
            elseif (i==table_height) && (j > 1) && (j < table_width)% 5
                % N1
                        sum=0;
                        valid_count=0;
                        rec=0;
                if block_valid_or_invalid_1(i-1,j-1) == 1
%                     sum=sum+ avg_matrix(1 + block_height * (i-1)  , 1 + block_width * (j-1)  );
                    sum=sum+ avg_matrix((i-1), (j-1));
                        valid_count=valid_count+1;
                end
                % N2
                if block_valid_or_invalid_1(i-1,j) == 1
%                      sum=sum+ avg_matrix(1 + block_height * (i-1)  , 1 + block_width * (j)  );
                     sum=sum+ avg_matrix((i-1), (j));
                        valid_count=valid_count+1;
                end
                % N3
                if block_valid_or_invalid_1(i-1,j+1) == 1
%                     sum=sum+ avg_matrix(1 + block_height * (i-1)  , 1 + block_width * (j+1)  );
                    sum=sum+ avg_matrix((i-1), (j+1));
                        valid_count=valid_count+1;
                end                
                % N4
                if block_valid_or_invalid_1(i,j+1) == 1
%                      sum=sum+ avg_matrix(1 + block_height * (i)  , 1 + block_width * (j+1)  );
                     sum=sum+ avg_matrix((i), (j+1));
                        valid_count=valid_count+1;
                end
                % N8
                if block_valid_or_invalid_1(i,j-1) == 1
%                      sum=sum+ avg_matrix(1 + block_height * (i)  , 1 + block_width * (j-1)  );
                     sum=sum+ avg_matrix((i), (j-1));
                        valid_count=valid_count+1;
                end  
                rec= round(sum/valid_count);
            image_data_recovered(1+block_height*(i-1),1+block_width*(j-1)) = rec;
            image_data_recovered(1+block_height*(i-1)+1,1+block_width*(j-1)) = rec;
            image_data_recovered(1+block_height*(i-1),1+block_width*(j-1)+1) = rec;
            image_data_recovered(1+block_height*(i-1)+1,1+block_width*(j-1)+1) = rec; 
            flag =1;
%             block_valid_or_invalid_1(i,j) = 1;
            elseif (i==1)&&(j==1)% 6             
                % N4
                         sum=0;
                        valid_count=0;
                        rec=0;
                if block_valid_or_invalid_1(i,j+1) == 1
%                     sum=sum+ avg_matrix(1 + block_height * (i)  , 1 + block_width * (j+1)  );
                    sum=sum+ avg_matrix((i), (j+1));
                        valid_count=valid_count+1;
                end
                % N5
                if block_valid_or_invalid_1(i+1,j+1) == 1
%                    sum=sum+ avg_matrix(1 + block_height * (i+1)  , 1 + block_width * (j+1)  );
                   sum=sum+ avg_matrix((i+1), (j+1));
                        valid_count=valid_count+1;
                end
                % N6
                if block_valid_or_invalid_1(i+1,j) == 1
%                     sum=sum+ avg_matrix(1 + block_height * (i+1)  , 1 + block_width * (j)  );
                    sum=sum+ avg_matrix((i+1), (j));
                        valid_count=valid_count+1;
                end 
               rec= round(sum/valid_count);
            image_data_recovered(1+block_height*(i-1),1+block_width*(j-1)) = rec;
            image_data_recovered(1+block_height*(i-1)+1,1+block_width*(j-1)) = rec;
            image_data_recovered(1+block_height*(i-1),1+block_width*(j-1)+1) = rec;
            image_data_recovered(1+block_height*(i-1)+1,1+block_width*(j-1)+1) = rec;
            flag =1;
%             block_valid_or_invalid_1(i,j) = 1;
            elseif (i==1)&&(j==table_width)% 7
                % N6
                        sum=0;
                        valid_count=0;
                        rec=0;
                if block_valid_or_invalid_1(i+1,j) == 1
%                     sum=sum+ avg_matrix(1 + block_height * (i+1)  , 1 + block_width * (j)  );
                    sum=sum+ avg_matrix((i+1),(j));
                        valid_count=valid_count+1;
                end
                % N7
                if block_valid_or_invalid_1(i+1,j-1) == 1
%                     sum=sum+ avg_matrix(1 + block_height * (i+1)  , 1 + block_width * (j-1)  );
                    sum=sum+ avg_matrix((i+1),(j-1));
                        valid_count=valid_count+1;
                end
                % N8
                if block_valid_or_invalid_1(i,j-1) == 1
%                     sum=sum+ avg_matrix(1 + block_height * (i)  , 1 + block_width * (j-1)  );
                    sum=sum+ avg_matrix((i),(j-1));
                        valid_count=valid_count+1;
                end     
              rec= round(sum/valid_count);
            image_data_recovered(1+block_height*(i-1),1+block_width*(j-1)) = rec;
            image_data_recovered(1+block_height*(i-1)+1,1+block_width*(j-1)) = rec;
            image_data_recovered(1+block_height*(i-1),1+block_width*(j-1)+1) = rec;
            image_data_recovered(1+block_height*(i-1)+1,1+block_width*(j-1)+1) = rec;
            flag =1;
%              block_valid_or_invalid_backup(i,j) = 1;
            elseif (i==table_height)&&(j==1)% 8
                % N2
                        sum=0;
                        valid_count=0;
                        rec=0;
                if block_valid_or_invalid_1(i-1,j) == 1
%                     sum=sum+ avg_matrix(1 + block_height * (i-1)  , 1 + block_width * (j)  );
                    sum=sum+ avg_matrix((i-1),(j));
                        valid_count=valid_count+1;
                end
                % N3
                if block_valid_or_invalid_1(i-1,j+1) == 1
%                    sum=sum+ avg_matrix(1 + block_height * (i-1)  , 1 + block_width * (j+1)  );
                   sum=sum+ avg_matrix((i-1),(j+1));
                        valid_count=valid_count+1;
                end                
                % N4
                if block_valid_or_invalid_1(i,j+1) == 1
%                     sum=sum+ avg_matrix(1 + block_height * (i)  , 1 + block_width * (j+1)  );
                    sum=sum+ avg_matrix((i),(j+1));
                        valid_count=valid_count+1;
                end 
                 rec= round(sum/valid_count);
            image_data_recovered(1+block_height*(i-1),1+block_width*(j-1)) = rec;
            image_data_recovered(1+block_height*(i-1)+1,1+block_width*(j-1)) = rec;
            image_data_recovered(1+block_height*(i-1),1+block_width*(j-1)+1) = rec;
            image_data_recovered(1+block_height*(i-1)+1,1+block_width*(j-1)+1) = rec;
            flag =1;
            elseif (i==table_height)&&(j==table_width)% 9
                % N1
                        sum=0;
                        valid_count=0;
                        rec=0;
                if block_valid_or_invalid_1(i-1,j-1) == 1
%                     sum=sum+ avg_matrix(1 + block_height * (i-1)  , 1 + block_width * (j-1)  );
                    sum=sum+ avg_matrix((i-1),(j-1));
                        valid_count=valid_count+1;
                end
                % N2
                if block_valid_or_invalid_1(i-1,j) == 1
%                     sum=sum+ avg_matrix(1 + block_height * (i-1)  , 1 + block_width * (j)  );
                    sum=sum+ avg_matrix((i-1),(j));
                        valid_count=valid_count+1;
                end
                % N8
                if block_valid_or_invalid_1(i,j-1) == 1
%                     sum=sum+ avg_matrix(1 + block_height * (i)  , 1 + block_width * (j-1)  );
                    sum=sum+ avg_matrix((i),(j-1));
                        valid_count=valid_count+1;
                end 
                 rec= round(sum/valid_count);
            image_data_recovered(1+block_height*(i-1),1+block_width*(j-1)) = rec;
            image_data_recovered(1+block_height*(i-1)+1,1+block_width*(j-1)) = rec;
            image_data_recovered(1+block_height*(i-1),1+block_width*(j-1)+1) = rec;
            image_data_recovered(1+block_height*(i-1)+1,1+block_width*(j-1)+1) = rec;
            flag =1;
%              block_valid_or_invalid_1(i,j) = 1;
            end
            
            if flag == 1
                block_valid_or_invalid_1(i,j) = 1;
            end
        end
%         
    end
end



block_equal_zero = 0;
for i = 1 : 1 : table_height
    for j = 1 : 1 : table_width
        if block_valid_or_invalid_1(i, j) == 0
            block_equal_zero = block_equal_zero + 1;
        end
    end
end
fprintf('The percentage of blocks not recovered after stage-2 tamper recovery is %0.4f%%\n', (block_equal_zero * 100) / (table_width * table_height));
figure('NumberTitle', 'off', 'Name', 'Image Data Recovered '); 
imshow(image_data_recovered); 
imwrite(image_data_recovered,'D:\image_recovery-master\data\Recovered\Boboon70.tif','tif'); 
% error_value = double(image_data(109:148,109:148)) - double(image_data_recovered(109:148,109:148));
% % % [peak_snr] = psnr(image_data_embed,image_data_recovered);
% % % fprintf('\nThe Recovered Image Peak-SNR value is %0.4f', peak_snr);


dif1=uint8(image_data_embed-image_data_recovered);
squared_error1 = dif1.^2;
    MSE1 = mean(squared_error1(:));
% MSE=sum(sum(dif).^2)/(512*512);
PSNR=10*log10((255*255)/MSE1);
% fprintf('\nMSE:%7.2f',MSE1);
fprintf('\nPSNR:%9.4f dB',PSNR);

nc_value = normxcorr2(image_data_embed, image_data_recovered);
nc_value = max(nc_value(:));
    fprintf('\nThe NC value is %0.4f \n', nc_value);
% title('Image Data Recovered');