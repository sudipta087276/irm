"""
Simplified Enhanced Forensic Analysis Module for Law Enforcement Investigations
This version works without OpenCV dependencies and focuses on PIL-based analysis
"""

import numpy as np
from PIL import Image, ExifTags
from datetime import datetime
import hashlib
import json
import warnings
from typing import Dict, List, Tuple, Optional, Any
import urllib.parse
import requests

class EnhancedForensicAnalyzerSimple:
    """Simplified law enforcement-grade forensic analysis without OpenCV dependencies"""
    
    def __init__(self):
        self.analysis_results = {}
        self.chain_of_custody = []
        self.device_fingerprints = {}
        self.gps_locations = {}
        self.tampering_timeline = []
        
        # Comprehensive EXIF tag mapping for forensic analysis
        self.exif_forensic_tags = {
            # Device Information
            'Make': 'device_manufacturer',
            'Model': 'device_model',
            'Software': 'editing_software',
            'LensMake': 'lens_manufacturer',
            'LensModel': 'lens_model',
            'BodySerialNumber': 'device_serial',
            'LensSerialNumber': 'lens_serial',
            
            # GPS Information
            'GPSInfo': 'gps_data',
            'GPSLatitude': 'gps_latitude',
            'GPSLongitude': 'gps_longitude',
            'GPSAltitude': 'gps_altitude',
            'GPSTimeStamp': 'gps_timestamp',
            'GPSDateStamp': 'gps_date',
            'GPSProcessingMethod': 'gps_processing_method',
            'GPSDestLatitude': 'destination_latitude',
            'GPSDestLongitude': 'destination_longitude',
            
            # Timestamp Information
            'DateTime': 'creation_datetime',
            'DateTimeOriginal': 'original_datetime',
            'DateTimeDigitized': 'digitized_datetime',
            'SubSecTime': 'subsecond_time',
            'SubSecTimeOriginal': 'original_subsecond',
            
            # Camera Settings (for device fingerprinting)
            'ExposureTime': 'exposure_time',
            'FNumber': 'f_number',
            'ISO': 'iso_speed',
            'FocalLength': 'focal_length',
            'Flash': 'flash_status',
            'WhiteBalance': 'white_balance',
            'MeteringMode': 'metering_mode',
            'ExposureProgram': 'exposure_program',
            'ColorSpace': 'color_space',
            
            # Location and Environmental
            'AmbientTemperature': 'temperature',
            'Humidity': 'humidity',
            'Pressure': 'pressure',
            'UserComment': 'user_comment',
            'Artist': 'artist_creator'
        }
    
    def extract_comprehensive_metadata(self, image_path: str) -> Dict[str, Any]:
        """Extract comprehensive forensic metadata including device and GPS information"""
        try:
            with Image.open(image_path) as img:
                forensic_metadata = {
                    'basic_info': self._extract_basic_info(img),
                    'device_info': self._extract_device_info(img),
                    'gps_info': self._extract_gps_info(img),
                    'timestamp_info': self._extract_timestamp_info(img),
                    'camera_settings': self._extract_camera_settings(img),
                    'forensic_indicators': self._extract_forensic_indicators(img),
                    'raw_exif': {}
                }
                
                # Extract raw EXIF data
                if hasattr(img, '_getexif') and img._getexif() is not None:
                    exif = img._getexif()
                    for tag_id, value in exif.items():
                        tag = ExifTags.TAGS.get(tag_id, tag_id)
                        forensic_metadata['raw_exif'][tag] = str(value)
                
                # Generate device fingerprint
                forensic_metadata['device_fingerprint'] = self._generate_device_fingerprint(forensic_metadata)
                
                # Analyze metadata for tampering indicators
                forensic_metadata['tampering_analysis'] = self._analyze_metadata_tampering(forensic_metadata)
                
                return forensic_metadata
                
        except Exception as e:
            return {"error": f"Comprehensive metadata extraction failed: {str(e)}"}
    
    def _get_color_depth(self, mode: str) -> int:
        """Get color depth in bits per pixel based on image mode"""
        mode_depths = {
            '1': 1,      # 1-bit pixels, black and white
            'L': 8,      # 8-bit pixels, grayscale
            'P': 8,      # 8-bit pixels, mapped to any other mode
            'RGB': 24,   # 3x8-bit pixels, true color
            'RGBA': 32,  # 4x8-bit pixels, true color with transparency
            'CMYK': 32,  # 4x8-bit pixels, color separation
            'YCbCr': 24, # 3x8-bit pixels, color video format
            'LAB': 24,   # 3x8-bit pixels, L*a*b color space
            'HSV': 24,   # 3x8-bit pixels, Hue, Saturation, Value
            'I': 32,     # 32-bit signed integer pixels
            'F': 32,     # 32-bit floating point pixels
            'LA': 16,    # 2x8-bit pixels, grayscale with transparency
            'RGBX': 32,  # 4x8-bit pixels, true color with padding
            'RGBa': 32,  # 4x8-bit pixels, true color with premultiplied alpha
        }
        return mode_depths.get(mode, 24)  # Default to 24-bit for unknown modes
    
    def _extract_basic_info(self, img: Image.Image) -> Dict[str, Any]:
        """Extract basic image information"""
        return {
            'format': img.format,
            'mode': img.mode,
            'size': img.size,
            'has_transparency': img.mode in ('RGBA', 'LA') or 'transparency' in img.info,
            'file_size_bytes': len(img.tobytes()) if hasattr(img, 'tobytes') else None,
            'color_depth': self._get_color_depth(img.mode)
        }
    
    def _extract_device_info(self, img: Image.Image) -> Dict[str, Any]:
        """Extract device manufacturer and model information"""
        device_info = {}
        
        if hasattr(img, '_getexif') and img._getexif() is not None:
            exif = img._getexif()
            
            # Device manufacturer
            device_info['manufacturer'] = exif.get(271, 'Unknown')  # Make
            device_info['model'] = exif.get(272, 'Unknown')  # Model
            device_info['serial_number'] = exif.get(42034, 'Unknown')  # BodySerialNumber
            
            # Software/editing information
            device_info['software'] = exif.get(305, 'Unknown')  # Software
            device_info['firmware_version'] = exif.get(36864, 'Unknown')  # ExifVersion
            
            # Lens information
            device_info['lens_manufacturer'] = exif.get(42035, 'Unknown')  # LensMake
            device_info['lens_model'] = exif.get(42036, 'Unknown')  # LensModel
            device_info['lens_serial'] = exif.get(42033, 'Unknown')  # LensSerialNumber
            
            # Device capabilities
            device_info['has_gps'] = 34853 in exif  # GPSInfo tag
            device_info['has_flash'] = exif.get(319, 0) != 0  # Flash
            
        return device_info
    
    def _extract_gps_info(self, img: Image.Image) -> Dict[str, Any]:
        """Extract GPS location and navigation data"""
        gps_info = {}
        
        try:
            if hasattr(img, '_getexif') and img._getexif() is not None:
                exif = img._getexif()
                
                if 34853 in exif:  # GPSInfo tag exists
                    gps_data = exif[34853]
                    
                    # Extract GPS coordinates
                    if 2 in gps_data and 4 in gps_data:  # GPSLatitude and GPSLongitude
                        lat = self._convert_gps_coordinates(gps_data[2], gps_data.get(1, 'N'))
                        lon = self._convert_gps_coordinates(gps_data[4], gps_data.get(3, 'E'))
                        
                        gps_info['latitude'] = lat
                        gps_info['longitude'] = lon
                        gps_info['coordinates'] = f"{lat}, {lon}"
                        
                        # Get location name using reverse geocoding
                        gps_info['location_name'] = self._reverse_geocode_location(lat, lon)
                        
                        # Calculate location accuracy
                        gps_info['location_accuracy'] = self._calculate_gps_accuracy(gps_data)
                    
                    # Extract altitude
                    if 6 in gps_data:
                        altitude = gps_data[6]
                        if isinstance(altitude, tuple):
                            gps_info['altitude'] = float(altitude[0]) / float(altitude[1]) if altitude[1] != 0 else 0
                        else:
                            gps_info['altitude'] = float(altitude)
                    
                    # Extract GPS timestamp
                    if 7 in gps_data and 29 in gps_data:
                        gps_time = self._convert_gps_timestamp(gps_data[7], gps_data[29])
                        gps_info['gps_timestamp'] = gps_time
                    
                    # Extract GPS processing method
                    if 31 in gps_data:
                        gps_info['processing_method'] = gps_data[31]
                    
                    # Extract destination coordinates
                    if 20 in gps_data and 22 in gps_data:
                        dest_lat = self._convert_gps_coordinates(gps_data[20], gps_data.get(19, 'N'))
                        dest_lon = self._convert_gps_coordinates(gps_data[22], gps_data.get(21, 'E'))
                        gps_info['destination_coordinates'] = f"{dest_lat}, {dest_lon}"
                    
                    # Extract movement data
                    if 13 in gps_data and 15 in gps_data:
                        gps_info['movement_direction'] = gps_data[13]  # GPSImgDirection
                        gps_info['movement_speed'] = gps_data[15]  # GPSSpeed
                
                else:
                    gps_info['status'] = 'No GPS data found'
            
            else:
                gps_info['status'] = 'No EXIF data available'
                
        except Exception as e:
            gps_info['error'] = f"GPS extraction failed: {str(e)}"
            gps_info['status'] = 'GPS extraction error'
        
        return gps_info
    
    def _convert_gps_coordinates(self, coordinates: tuple, direction: str) -> float:
        """Convert GPS coordinates from EXIF format to decimal degrees"""
        try:
            if isinstance(coordinates, tuple) and len(coordinates) == 3:
                degrees = float(coordinates[0])
                minutes = float(coordinates[1])
                seconds = float(coordinates[2])
                
                decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)
                
                # Apply direction
                if direction in ['S', 'W']:
                    decimal = -decimal
                
                return round(decimal, 6)
            else:
                return 0.0
        except Exception:
            return 0.0
    
    def _reverse_geocode_location(self, latitude: float, longitude: float) -> Dict[str, str]:
        """Get location name from GPS coordinates using Nominatim API"""
        try:
            # Use OpenStreetMap Nominatim API (free, no API key required)
            url = f"https://nominatim.openstreetmap.org/reverse?format=json&lat={latitude}&lon={longitude}&zoom=18&addressdetails=1"
            
            headers = {'User-Agent': 'ForensicImageAnalyzer/1.0'}
            response = requests.get(url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                address = data.get('address', {})
                
                return {
                    'full_address': data.get('display_name', 'Unknown location'),
                    'country': address.get('country', 'Unknown'),
                    'state': address.get('state', 'Unknown'),
                    'city': address.get('city', address.get('town', address.get('village', 'Unknown'))),
                    'road': address.get('road', 'Unknown'),
                    'house_number': address.get('house_number', 'Unknown'),
                    'postcode': address.get('postcode', 'Unknown'),
                    'confidence': 'High' if address else 'Low'
                }
            else:
                return {'error': f'Geocoding API returned status {response.status_code}'}
                
        except Exception as e:
            return {'error': f'Reverse geocoding failed: {str(e)}'}
    
    def _calculate_gps_accuracy(self, gps_data: Dict) -> Dict[str, Any]:
        """Calculate GPS location accuracy from metadata"""
        try:
            accuracy_info = {}
            
            # Horizontal accuracy (if available)
            if 16 in gps_data:  # GPSHPositioningError
                accuracy_info['horizontal_accuracy'] = float(gps_data[16])
            
            # Vertical accuracy (if available)
            if 17 in gps_data:  # GPSVPositioningError
                accuracy_info['vertical_accuracy'] = float(gps_data[17])
            
            # Dilution of precision (DOP) values
            if 11 in gps_data:  # GPSDOP
                accuracy_info['dilution_of_precision'] = float(gps_data[11])
            
            # Satellite information
            if 24 in gps_data:  # GPSSatellites
                accuracy_info['satellites_used'] = str(gps_data[24])
            
            # Calculate estimated accuracy based on available satellites
            if 'satellites_used' in accuracy_info:
                sat_count = len(str(accuracy_info['satellites_used']).split(','))
                if sat_count >= 8:
                    accuracy_info['estimated_accuracy'] = 'High (≤ 5 meters)'
                elif sat_count >= 4:
                    accuracy_info['estimated_accuracy'] = 'Medium (5-15 meters)'
                else:
                    accuracy_info['estimated_accuracy'] = 'Low (> 15 meters)'
            else:
                accuracy_info['estimated_accuracy'] = 'Unknown'
            
            return accuracy_info
            
        except Exception as e:
            return {'error': f'GPS accuracy calculation failed: {str(e)}'}
    
    def _convert_gps_timestamp(self, gps_time_tuple: tuple, gps_date_str: str) -> str:
        """Convert GPS timestamp to readable format"""
        try:
            if isinstance(gps_time_tuple, tuple) and len(gps_time_tuple) == 3:
                hours = int(gps_time_tuple[0])
                minutes = int(gps_time_tuple[1])
                seconds = float(gps_time_tuple[2])
                
                # Parse GPS date
                if gps_date_str and ':' in gps_date_str:
                    year, month, day = gps_date_str.split(':')
                    dt = datetime(int(year), int(month), int(day), hours, minutes, int(seconds))
                    return dt.isoformat()
                else:
                    return f"{hours:02d}:{minutes:02d}:{int(seconds):02d}"
            else:
                return "Invalid GPS time format"
                
        except Exception as e:
            return f"GPS timestamp conversion error: {str(e)}"
    
    def _extract_timestamp_info(self, img: Image.Image) -> Dict[str, Any]:
        """Extract comprehensive timestamp information"""
        timestamp_info = {}
        
        try:
            if hasattr(img, '_getexif') and img._getexif() is not None:
                exif = img._getexif()
                
                # Primary timestamps
                timestamp_info['creation_datetime'] = self._parse_exif_datetime(exif.get(306, ''))  # DateTime
                timestamp_info['original_datetime'] = self._parse_exif_datetime(exif.get(36867, ''))  # DateTimeOriginal
                timestamp_info['digitized_datetime'] = self._parse_exif_datetime(exif.get(36868, ''))  # DateTimeDigitized
                
                # Subsecond timing
                timestamp_info['subsecond_time'] = exif.get(37520, '')  # SubSecTime
                timestamp_info['original_subsecond'] = exif.get(37521, '')  # SubSecTimeOriginal
                timestamp_info['digitized_subsecond'] = exif.get(37522, '')  # SubSecTimeDigitized
                
                # Timezone information (if available)
                timestamp_info['timezone_offset'] = exif.get(34858, '')  # TimeZoneOffset
                
                # Analyze timestamp consistency
                timestamp_info['consistency_analysis'] = self._analyze_timestamp_consistency(timestamp_info)
                
        except Exception as e:
            timestamp_info['error'] = f"Timestamp extraction failed: {str(e)}"
        
        return timestamp_info
    
    def _parse_exif_datetime(self, datetime_str: str) -> str:
        """Parse EXIF datetime string to ISO format"""
        try:
            if datetime_str and len(datetime_str) >= 19:
                # EXIF format: "YYYY:MM:DD HH:MM:SS"
                date_part = datetime_str[:10].replace(':', '-')
                time_part = datetime_str[11:19]
                return f"{date_part}T{time_part}"
            return ""
        except Exception:
            return ""
    
    def _analyze_timestamp_consistency(self, timestamp_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze timestamp consistency for tampering indicators"""
        try:
            consistency_analysis = {}
            
            # Check if timestamps are present
            creation = timestamp_info.get('creation_datetime', '')
            original = timestamp_info.get('original_datetime', '')
            digitized = timestamp_info.get('digitized_datetime', '')
            
            # Logical consistency checks
            consistency_analysis['has_creation_time'] = bool(creation)
            consistency_analysis['has_original_time'] = bool(original)
            consistency_analysis['has_digitized_time'] = bool(digitized)
            
            # Check if original time precedes creation time (suspicious)
            if original and creation:
                try:
                    orig_dt = datetime.fromisoformat(original.replace('T', ' '))
                    creat_dt = datetime.fromisoformat(creation.replace('T', ' '))
                    consistency_analysis['original_before_creation'] = orig_dt < creat_dt
                    consistency_analysis['time_order_suspicious'] = orig_dt > creat_dt
                except:
                    consistency_analysis['time_order_suspicious'] = False
            
            # Check for identical timestamps (possible cloning)
            if original and creation and digitized:
                consistency_analysis['all_timestamps_identical'] = (original == creation == digitized)
                if consistency_analysis['all_timestamps_identical']:
                    consistency_analysis['cloning_indicator'] = True
            
            return consistency_analysis
            
        except Exception as e:
            return {'error': f'Timestamp consistency analysis failed: {str(e)}'}
    
    def _extract_camera_settings(self, img: Image.Image) -> Dict[str, Any]:
        """Extract camera settings for device fingerprinting"""
        camera_settings = {}
        
        try:
            if hasattr(img, '_getexif') and img._getexif() is not None:
                exif = img._getexif()
                
                # Exposure settings
                camera_settings['exposure_time'] = self._format_fraction(exif.get(33434, ''))  # ExposureTime
                camera_settings['f_number'] = self._format_fraction(exif.get(33437, ''))  # FNumber
                camera_settings['iso_speed'] = exif.get(34855, '')  # ISOSpeedRatings
                camera_settings['focal_length'] = self._format_fraction(exif.get(37386, ''))  # FocalLength
                
                # Camera mode settings
                camera_settings['flash'] = self._decode_flash_status(exif.get(319, 0))  # Flash
                camera_settings['white_balance'] = self._decode_white_balance(exif.get(37384, ''))  # WhiteBalance
                camera_settings['metering_mode'] = self._decode_metering_mode(exif.get(37383, ''))  # MeteringMode
                camera_settings['exposure_program'] = self._decode_exposure_program(exif.get(34850, ''))  # ExposureProgram
                camera_settings['color_space'] = self._decode_color_space(exif.get(40961, ''))  # ColorSpace
                
                # Advanced settings
                camera_settings['aperture'] = self._format_fraction(exif.get(37378, ''))  # ApertureValue
                camera_settings['brightness'] = self._format_fraction(exif.get(37379, ''))  # BrightnessValue
                camera_settings['exposure_bias'] = self._format_fraction(exif.get(37380, ''))  # ExposureBiasValue
                camera_settings['max_aperture'] = self._format_fraction(exif.get(37381, ''))  # MaxApertureValue
                
                # Image characteristics
                camera_settings['width'] = exif.get(40962, '')  # PixelXDimension
                camera_settings['height'] = exif.get(40963, '')  # PixelYDimension
                
        except Exception as e:
            camera_settings['error'] = f"Camera settings extraction failed: {str(e)}"
        
        return camera_settings
    
    def _format_fraction(self, fraction_tuple: tuple) -> str:
        """Format fraction tuple as string"""
        try:
            if isinstance(fraction_tuple, tuple) and len(fraction_tuple) == 2:
                numerator, denominator = fraction_tuple
                if denominator != 0:
                    if numerator == 0:
                        return "0"
                    elif numerator == denominator:
                        return "1"
                    else:
                        return f"{numerator}/{denominator}"
            return str(fraction_tuple)
        except Exception:
            return str(fraction_tuple)
    
    def _decode_flash_status(self, flash_value: int) -> Dict[str, Any]:
        """Decode flash status from EXIF value"""
        flash_info = {'raw_value': flash_value}
        
        try:
            if flash_value == 0:
                flash_info['status'] = 'No flash'
                flash_info['fired'] = False
            elif flash_value == 1:
                flash_info['status'] = 'Flash fired'
                flash_info['fired'] = True
            elif flash_value == 5:
                flash_info['status'] = 'Flash fired, strobe return light not detected'
                flash_info['fired'] = True
            elif flash_value == 7:
                flash_info['status'] = 'Flash fired, strobe return light detected'
                flash_info['fired'] = True
            elif flash_value == 9:
                flash_info['status'] = 'Flash fired, compulsory flash mode'
                flash_info['fired'] = True
            elif flash_value == 13:
                flash_info['status'] = 'Flash fired, compulsory flash mode, return light not detected'
                flash_info['fired'] = True
            elif flash_value == 15:
                flash_info['status'] = 'Flash fired, compulsory flash mode, return light detected'
                flash_info['fired'] = True
            elif flash_value == 16:
                flash_info['status'] = 'Flash did not fire, compulsory flash mode'
                flash_info['fired'] = False
            elif flash_value == 24:
                flash_info['status'] = 'Flash did not fire, auto mode'
                flash_info['fired'] = False
            elif flash_value == 25:
                flash_info['status'] = 'Flash did not fire, auto mode, return light not detected'
                flash_info['fired'] = False
            elif flash_value == 29:
                flash_info['status'] = 'Flash did not fire, auto mode, return light detected'
                flash_info['fired'] = False
            elif flash_value == 31:
                flash_info['status'] = 'No flash function'
                flash_info['fired'] = False
            elif flash_value == 32:
                flash_info['status'] = 'Flash did not fire, auto mode'
                flash_info['fired'] = False
            elif flash_value == 65:
                flash_info['status'] = 'Flash fired, red-eye reduction mode'
                flash_info['fired'] = True
            elif flash_value == 69:
                flash_info['status'] = 'Flash fired, red-eye reduction mode, return light not detected'
                flash_info['fired'] = True
            elif flash_value == 71:
                flash_info['status'] = 'Flash fired, red-eye reduction mode, return light detected'
                flash_info['fired'] = True
            elif flash_value == 73:
                flash_info['status'] = 'Flash fired, compulsory flash mode, red-eye reduction mode'
                flash_info['fired'] = True
            elif flash_value == 77:
                flash_info['status'] = 'Flash fired, compulsory flash mode, red-eye reduction mode, return light not detected'
                flash_info['fired'] = True
            elif flash_value == 79:
                flash_info['status'] = 'Flash fired, compulsory flash mode, red-eye reduction mode, return light detected'
                flash_info['fired'] = True
            elif flash_value == 89:
                flash_info['status'] = 'Flash fired, auto mode, red-eye reduction mode'
                flash_info['fired'] = True
            elif flash_value == 93:
                flash_info['status'] = 'Flash fired, auto mode, return light not detected, red-eye reduction mode'
                flash_info['fired'] = True
            elif flash_value == 95:
                flash_info['status'] = 'Flash fired, auto mode, return light detected, red-eye reduction mode'
                flash_info['fired'] = True
            else:
                flash_info['status'] = f'Unknown flash value: {flash_value}'
                flash_info['fired'] = bool(flash_value & 1)
            
        except Exception:
            flash_info['status'] = f'Error decoding flash value: {flash_value}'
            flash_info['fired'] = False
        
        return flash_info
    
    def _decode_white_balance(self, wb_value: int) -> str:
        """Decode white balance setting"""
        wb_map = {
            0: 'Auto white balance',
            1: 'Manual white balance',
            2: 'One push manual white balance',
            3: 'Daylight',
            4: 'Cloudy',
            5: 'Shade',
            6: 'Tungsten',
            7: 'Fluorescent',
            8: 'Flash',
            9: 'Underwater',
            10: 'Custom white balance',
            11: 'Color temperature',
            12: 'Custom white balance 2',
            13: 'Custom white balance 3',
            14: 'Custom white balance 4',
            15: 'Custom white balance 5',
            16: 'Custom white balance 6',
            17: 'Custom white balance 7'
        }
        return wb_map.get(wb_value, f'Unknown white balance: {wb_value}')
    
    def _decode_metering_mode(self, metering_value: int) -> str:
        """Decode metering mode"""
        metering_map = {
            0: 'Unknown',
            1: 'Average',
            2: 'Center-weighted average',
            3: 'Spot',
            4: 'Multi-spot',
            5: 'Pattern',
            6: 'Partial',
            255: 'Other'
        }
        return metering_map.get(metering_value, f'Unknown metering mode: {metering_value}')
    
    def _decode_exposure_program(self, program_value: int) -> str:
        """Decode exposure program"""
        program_map = {
            0: 'Not defined',
            1: 'Manual',
            2: 'Normal program',
            3: 'Aperture priority',
            4: 'Shutter priority',
            5: 'Creative program',
            6: 'Action program',
            7: 'Portrait mode',
            8: 'Landscape mode'
        }
        return program_map.get(program_value, f'Unknown program: {program_value}')
    
    def _decode_color_space(self, color_space_value: int) -> str:
        """Decode color space"""
        color_space_map = {
            1: 'sRGB',
            2: 'Adobe RGB',
            65535: 'Uncalibrated'
        }
        return color_space_map.get(color_space_value, f'Unknown color space: {color_space_value}')
    
    def _extract_forensic_indicators(self, img: Image.Image) -> Dict[str, Any]:
        """Extract forensic indicators from metadata"""
        forensic_indicators = {}
        
        try:
            if hasattr(img, '_getexif') and img._getexif() is not None:
                exif = img._getexif()
                
                # Check for editing software (indicates post-processing)
                software = exif.get(305, '')  # Software
                forensic_indicators['editing_software'] = software if software else 'Unknown'
                forensic_indicators['has_editing_software'] = bool(software)
                
                # Check for artist/creator information
                artist = exif.get(315, '')  # Artist
                forensic_indicators['artist_creator'] = artist if artist else 'Unknown'
                forensic_indicators['has_artist_info'] = bool(artist)
                
                # Check for copyright information
                copyright = exif.get(33432, '')  # Copyright
                forensic_indicators['copyright_info'] = copyright if copyright else 'Unknown'
                forensic_indicators['has_copyright'] = bool(copyright)
                
                # Check for user comments
                user_comment = exif.get(37510, '')  # UserComment
                forensic_indicators['user_comment'] = user_comment if user_comment else 'None'
                forensic_indicators['has_user_comment'] = bool(user_comment)
                
                # Check for thumbnail data (indicates camera processing)
                forensic_indicators['has_thumbnail'] = 513 in exif  # JPEGInterchangeFormat
                
                # Check for custom rendering
                custom_rendered = exif.get(41985, 0)  # CustomRendered
                forensic_indicators['custom_rendered'] = custom_rendered != 0
                
                # Check for gain control (indicates low light processing)
                gain_control = exif.get(41991, 0)  # GainControl
                forensic_indicators['gain_control_applied'] = gain_control != 0
                
        except Exception as e:
            forensic_indicators['error'] = f"Forensic indicators extraction failed: {str(e)}"
        
        return forensic_indicators
    
    def _generate_device_fingerprint(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a unique fingerprint for the device based on metadata"""
        try:
            device_fingerprint = {}
            
            # Combine device characteristics
            device_info = metadata.get('device_info', {})
            camera_settings = metadata.get('camera_settings', {})
            
            # Create device signature
            device_signature = []
            
            # Device manufacturer and model
            manufacturer = device_info.get('manufacturer', 'Unknown')
            model = device_info.get('model', 'Unknown')
            device_signature.append(f"{manufacturer}_{model}")
            
            # Camera capabilities
            if camera_settings.get('color_space'):
                device_signature.append(f"color_{camera_settings['color_space']}")
            
            # Lens information
            lens_make = device_info.get('lens_manufacturer', 'Unknown')
            lens_model = device_info.get('lens_model', 'Unknown')
            device_signature.append(f"lens_{lens_make}_{lens_model}")
            
            # Generate hash-based fingerprint
            signature_string = "|".join(device_signature)
            device_fingerprint['hash'] = hashlib.md5(signature_string.encode()).hexdigest()
            device_fingerprint['signature'] = signature_string
            device_fingerprint['confidence'] = 'High' if manufacturer != 'Unknown' else 'Low'
            
            # Device classification
            device_fingerprint['device_type'] = self._classify_device_type(manufacturer, model)
            device_fingerprint['likely_smartphone'] = self._is_likely_smartphone(manufacturer, model)
            
            return device_fingerprint
            
        except Exception as e:
            return {'error': f'Device fingerprint generation failed: {str(e)}'}
    
    def _classify_device_type(self, manufacturer: str, model: str) -> str:
        """Classify the device type based on manufacturer and model"""
        manufacturer_lower = manufacturer.lower()
        model_lower = model.lower()
        
        # Smartphone manufacturers
        smartphone_brands = ['apple', 'samsung', 'google', 'huawei', 'xiaomi', 'oneplus', 'oppo', 'vivo']
        if any(brand in manufacturer_lower for brand in smartphone_brands):
            return 'Smartphone'
        
        # Camera manufacturers
        camera_brands = ['canon', 'nikon', 'sony', 'fujifilm', 'panasonic', 'olympus', 'pentax']
        if any(brand in manufacturer_lower for brand in camera_brands):
            return 'Digital Camera'
        
        # Tablet manufacturers
        tablet_keywords = ['ipad', 'tablet', 'samsung tab']
        if any(keyword in model_lower for keyword in tablet_keywords):
            return 'Tablet'
        
        # Drone manufacturers
        drone_brands = ['dji', 'parrot', 'autel']
        if any(brand in manufacturer_lower for brand in drone_brands):
            return 'Drone'
        
        return 'Unknown Device Type'
    
    def _is_likely_smartphone(self, manufacturer: str, model: str) -> bool:
        """Determine if device is likely a smartphone"""
        manufacturer_lower = manufacturer.lower()
        model_lower = model.lower()
        
        smartphone_indicators = [
            'iphone', 'galaxy', 'pixel', 'huawei', 'xiaomi', 'oneplus',
            'oppo', 'vivo', 'samsung', 'google'
        ]
        
        return any(indicator in manufacturer_lower or indicator in model_lower 
                  for indicator in smartphone_indicators)
    
    def _analyze_metadata_tampering(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze metadata for signs of tampering or manipulation"""
        try:
            tampering_analysis = {}
            
            # Check for suspicious software
            forensic_indicators = metadata.get('forensic_indicators', {})
            software = forensic_indicators.get('editing_software', 'Unknown')
            
            editing_software = [
                'photoshop', 'lightroom', 'gimp', 'paint', 'corel', 'canva',
                'snapseed', 'vsco', 'instagram', 'facebook', 'whatsapp'
            ]
            
            tampering_analysis['editing_detected'] = any(
                editor in software.lower() for editor in editing_software
            )
            tampering_analysis['editing_software'] = software
            
            # Check timestamp consistency
            timestamp_info = metadata.get('timestamp_info', {})
            consistency = timestamp_info.get('consistency_analysis', {})
            
            tampering_analysis['timestamp_suspicious'] = consistency.get('time_order_suspicious', False)
            tampering_analysis['identical_timestamps'] = consistency.get('all_timestamps_identical', False)
            
            # Check GPS vs timestamp consistency
            gps_info = metadata.get('gps_info', {})
            if gps_info.get('coordinates') and timestamp_info.get('creation_datetime'):
                tampering_analysis['has_gps_timestamp'] = bool(gps_info.get('gps_timestamp'))
                
                # Simple heuristic: if GPS exists but timestamp is very old, might be suspicious
                try:
                    creation_time = datetime.fromisoformat(timestamp_info['creation_datetime'].replace('T', ' '))
                    if (datetime.now() - creation_time).days > 365:
                        tampering_analysis['very_old_timestamp'] = True
                except:
                    pass
            
            # Check for custom rendering
            tampering_analysis['custom_rendering'] = forensic_indicators.get('custom_rendered', False)
            tampering_analysis['gain_control'] = forensic_indicators.get('gain_control_applied', False)
            
            # Overall tampering score
            tampering_score = 0
            if tampering_analysis['editing_detected']:
                tampering_score += 3
            if tampering_analysis['timestamp_suspicious']:
                tampering_score += 2
            if tampering_analysis['identical_timestamps']:
                tampering_score += 2
            if tampering_analysis['custom_rendering']:
                tampering_score += 1
            if tampering_analysis['gain_control']:
                tampering_score += 1
            if tampering_analysis.get('very_old_timestamp'):
                tampering_score += 1
            
            tampering_analysis['metadata_tampering_score'] = tampering_score
            tampering_analysis['tampering_likelihood'] = self._assess_metadata_tampering_likelihood(tampering_score)
            
            return tampering_analysis
            
        except Exception as e:
            return {'error': f'Metadata tampering analysis failed: {str(e)}'}
    
    def _assess_metadata_tampering_likelihood(self, tampering_score: int) -> str:
        """Assess likelihood of metadata tampering based on score"""
        if tampering_score >= 6:
            return 'High likelihood of metadata tampering'
        elif tampering_score >= 3:
            return 'Moderate likelihood of metadata tampering'
        elif tampering_score >= 1:
            return 'Low likelihood of metadata tampering'
        else:
            return 'No significant metadata tampering indicators'
    
    def detect_tampering_device(self, original_metadata: Dict[str, Any], tampered_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Detect which device was used for tampering by comparing original vs tampered metadata"""
        try:
            tampering_device_analysis = {
                'devices_involved': [],
                'tampering_indicators': [],
                'device_switches': [],
                'location_changes': [],
                'timeline_anomalies': [],
                'confidence_score': 0.0
            }
            
            # Extract device information from both images
            orig_device = original_metadata.get('device_info', {})
            orig_device_fingerprint = original_metadata.get('device_fingerprint', {})
            
            tampered_device = tampered_metadata.get('device_info', {})
            tampered_device_fingerprint = tampered_metadata.get('device_fingerprint', {})
            
            # Compare device fingerprints
            if orig_device_fingerprint.get('hash') != tampered_device_fingerprint.get('hash'):
                tampering_device_analysis['devices_involved'].append({
                    'original_device': {
                        'manufacturer': orig_device.get('manufacturer', 'Unknown'),
                        'model': orig_device.get('model', 'Unknown'),
                        'fingerprint': orig_device_fingerprint.get('hash', 'Unknown')
                    },
                    'tampering_device': {
                        'manufacturer': tampered_device.get('manufacturer', 'Unknown'),
                        'model': tampered_device.get('model', 'Unknown'),
                        'fingerprint': tampered_device_fingerprint.get('hash', 'Unknown')
                    },
                    'analysis': 'Different devices detected'
                })
                
                tampering_device_analysis['device_switches'].append({
                    'from': f"{orig_device.get('manufacturer', 'Unknown')} {orig_device.get('model', 'Unknown')}",
                    'to': f"{tampered_device.get('manufacturer', 'Unknown')} {tampered_device.get('model', 'Unknown')}",
                    'confidence': 'High'
                })
            
            # Compare GPS locations
            orig_gps = original_metadata.get('gps_info', {})
            tampered_gps = tampered_metadata.get('gps_info', {})
            
            if orig_gps.get('coordinates') and tampered_gps.get('coordinates'):
                if orig_gps['coordinates'] != tampered_gps['coordinates']:
                    distance = self._calculate_distance(
                        orig_gps.get('latitude', 0), orig_gps.get('longitude', 0),
                        tampered_gps.get('latitude', 0), tampered_gps.get('longitude', 0)
                    )
                    
                    tampering_device_analysis['location_changes'].append({
                        'original_location': orig_gps.get('coordinates', 'Unknown'),
                        'tampered_location': tampered_gps.get('coordinates', 'Unknown'),
                        'distance_km': distance,
                        'location_name_change': orig_gps.get('location_name', {}).get('full_address', 'Unknown') != 
                                              tampered_gps.get('location_name', {}).get('full_address', 'Unknown'),
                        'analysis': f'Location changed by {distance:.2f} km'
                    })
            
            # Compare timestamps
            orig_timestamps = original_metadata.get('timestamp_info', {})
            tampered_timestamps = tampered_metadata.get('timestamp_info', {})
            
            orig_creation = orig_timestamps.get('creation_datetime', '')
            tampered_creation = tampered_timestamps.get('creation_datetime', '')
            
            if orig_creation and tampered_creation:
                time_diff = self._calculate_time_difference(orig_creation, tampered_creation)
                if abs(time_diff) > 3600:  # More than 1 hour difference
                    tampering_device_analysis['timeline_anomalies'].append({
                        'original_time': orig_creation,
                        'tampered_time': tampered_creation,
                        'time_difference_hours': time_diff / 3600,
                        'analysis': f'Timestamp changed by {time_diff/3600:.1f} hours'
                    })
            
            # Check for editing software
            orig_forensic = original_metadata.get('forensic_indicators', {})
            tampered_forensic = tampered_metadata.get('forensic_indicators', {})
            
            if tampered_forensic.get('has_editing_software') and not orig_forensic.get('has_editing_software'):
                tampering_device_analysis['tampering_indicators'].append({
                    'type': 'editing_software_detected',
                    'software': tampered_forensic.get('editing_software', 'Unknown'),
                    'confidence': 'High'
                })
            
            # Calculate overall confidence
            confidence_factors = [
                len(tampering_device_analysis['device_switches']) > 0,
                len(tampering_device_analysis['location_changes']) > 0,
                len(tampering_device_analysis['timeline_anomalies']) > 0,
                len(tampering_device_analysis['tampering_indicators']) > 0
            ]
            
            tampering_device_analysis['confidence_score'] = sum(confidence_factors) / len(confidence_factors)
            
            return tampering_device_analysis
            
        except Exception as e:
            return {'error': f'Tampering device detection failed: {str(e)}', 'confidence_score': 0.0}
    
    def _calculate_distance(self, lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate distance between two GPS coordinates in kilometers"""
        try:
            # Haversine formula
            from math import radians, cos, sin, asin, sqrt
            
            # Convert to radians
            lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
            
            # Haversine formula
            dlat = lat2 - lat1
            dlon = lon2 - lon1
            a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
            c = 2 * asin(sqrt(a))
            
            # Radius of earth in kilometers
            r = 6371
            
            return c * r
            
        except Exception:
            return 0.0
    
    def _calculate_time_difference(self, time1_str: str, time2_str: str) -> float:
        """Calculate time difference in seconds between two ISO datetime strings"""
        try:
            from datetime import datetime
            
            # Parse ISO format datetime strings
            time1 = datetime.fromisoformat(time1_str.replace('T', ' '))
            time2 = datetime.fromisoformat(time2_str.replace('T', ' '))
            
            return abs((time2 - time1).total_seconds())
            
        except Exception as e:
            return 0.0
    
    def create_forensic_evidence_chain(self, image_path: str, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Create a comprehensive forensic evidence chain for law enforcement"""
        try:
            evidence_chain = {
                'case_id': self._generate_case_id(),
                'evidence_id': self._generate_evidence_id(image_path),
                'chain_of_custody': [],
                'forensic_timeline': [],
                'device_evidence': {},
                'location_evidence': {},
                'legal_metadata': {},
                'investigation_status': 'Active'
            }
            
            # Add initial evidence entry
            evidence_chain['chain_of_custody'].append({
                'timestamp': datetime.now().isoformat(),
                'action': 'Evidence Collected',
                'handler': 'Digital Forensic System',
                'location': 'Forensic Laboratory',
                'description': f'Image evidence collected from {image_path}',
                'integrity_hash': analysis_results.get('image_hash', {}).get('sha256', 'Unknown')
            })
            
            # Add device evidence
            device_info = analysis_results.get('device_info', {})
            if device_info:
                evidence_chain['device_evidence'] = {
                    'primary_device': {
                        'manufacturer': device_info.get('manufacturer', 'Unknown'),
                        'model': device_info.get('model', 'Unknown'),
                        'serial_number': device_info.get('serial_number', 'Unknown'),
                        'software': device_info.get('software', 'Unknown')
                    },
                    'device_fingerprint': analysis_results.get('device_fingerprint', {}),
                    'camera_settings': analysis_results.get('camera_settings', {})
                }
            
            # Add location evidence
            gps_info = analysis_results.get('gps_info', {})
            if gps_info and gps_info.get('coordinates'):
                evidence_chain['location_evidence'] = {
                    'gps_coordinates': gps_info.get('coordinates'),
                    'location_name': gps_info.get('location_name', {}),
                    'accuracy': gps_info.get('location_accuracy', {}),
                    'timestamp': gps_info.get('gps_timestamp', 'Unknown')
                }
            
            # Add forensic timeline
            timestamp_info = analysis_results.get('timestamp_info', {})
            if timestamp_info:
                evidence_chain['forensic_timeline'].append({
                    'event': 'Image Creation',
                    'timestamp': timestamp_info.get('creation_datetime', 'Unknown'),
                    'source': 'EXIF Metadata',
                    'confidence': 'High' if timestamp_info.get('creation_datetime') else 'Low'
                })
            
            # Add tampering analysis if available
            tampering_analysis = analysis_results.get('tampering_analysis', {})
            if tampering_analysis and tampering_analysis.get('metadata_tampering_score', 0) > 0:
                evidence_chain['forensic_timeline'].append({
                    'event': 'Metadata Tampering Detected',
                    'timestamp': datetime.now().isoformat(),
                    'source': 'Forensic Analysis',
                    'confidence': 'High' if tampering_analysis.get('metadata_tampering_score', 0) > 3 else 'Medium',
                    'details': tampering_analysis
                })
            
            # Add legal metadata
            evidence_chain['legal_metadata'] = {
                'evidence_type': 'Digital Image',
                'collection_method': 'Automated Forensic Analysis',
                'analysis_tools': ['EnhancedForensicAnalyzerSimple v1.0'],
                'admissibility_notes': 'Digital evidence collected using validated forensic tools',
                'custodian': 'Digital Forensic Laboratory',
                'retention_period': 'Per legal requirements'
            }
            
            return evidence_chain
            
        except Exception as e:
            return {'error': f'Evidence chain creation failed: {str(e)}'}
    
    def _generate_case_id(self) -> str:
        """Generate a unique case ID"""
        return f"CASE-{datetime.now().strftime('%Y%m%d')}-{hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8].upper()}"
    
    def _generate_evidence_id(self, image_path: str) -> str:
        """Generate a unique evidence ID based on image path and timestamp"""
        path_hash = hashlib.md5(image_path.encode()).hexdigest()[:8]
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        return f"EVID-{timestamp}-{path_hash.upper()}"
    
    def generate_investigation_report(self, evidence_chain: Dict[str, Any], analysis_results: Dict[str, Any]) -> str:
        """Generate a comprehensive investigation report for law enforcement"""
        try:
            report = []
            
            # Header
            report.append("=" * 80)
            report.append("DIGITAL FORENSIC INVESTIGATION REPORT")
            report.append("LAW ENFORCEMENT EVIDENCE ANALYSIS")
            report.append("=" * 80)
            report.append("")
            
            # Case Information
            report.append(f"Case ID: {evidence_chain.get('case_id', 'Unknown')}")
            report.append(f"Evidence ID: {evidence_chain.get('evidence_id', 'Unknown')}")
            report.append(f"Investigation Status: {evidence_chain.get('investigation_status', 'Unknown')}")
            report.append(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            report.append("")
            
            # Executive Summary
            report.append("EXECUTIVE SUMMARY")
            report.append("-" * 40)
            
            tampering_score = analysis_results.get('tampering_analysis', {}).get('metadata_tampering_score', 0)
            tampering_likelihood = analysis_results.get('tampering_analysis', {}).get('tampering_likelihood', 'Unknown')
            
            if tampering_score >= 7:
                report.append("🚨 HIGH PRIORITY: Strong evidence of digital tampering detected")
            elif tampering_score >= 4:
                report.append("⚡ MODERATE PRIORITY: Evidence suggests possible tampering")
            elif tampering_score >= 2:
                report.append("ℹ️ LOW PRIORITY: Minor tampering indicators present")
            else:
                report.append("✅ CLEAR: No significant tampering evidence detected")
            
            report.append(f"Forensic Confidence Score: {tampering_score:.1f}/10")
            report.append(f"Tampering Assessment: {tampering_likelihood}")
            report.append("")
            
            # Device Evidence
            device_evidence = evidence_chain.get('device_evidence', {})
            if device_evidence:
                report.append("DEVICE EVIDENCE")
                report.append("-" * 40)
                
                primary_device = device_evidence.get('primary_device', {})
                report.append(f"Device Manufacturer: {primary_device.get('manufacturer', 'Unknown')}")
                report.append(f"Device Model: {primary_device.get('model', 'Unknown')}")
                report.append(f"Device Serial: {primary_device.get('serial_number', 'Unknown')}")
                report.append(f"Software Version: {primary_device.get('software', 'Unknown')}")
                
                device_fingerprint = device_evidence.get('device_fingerprint', {})
                report.append(f"Device Fingerprint: {device_fingerprint.get('hash', 'Unknown')}")
                report.append(f"Device Type: {device_fingerprint.get('device_type', 'Unknown')}")
                report.append("")
            
            # Location Evidence
            location_evidence = evidence_chain.get('location_evidence', {})
            if location_evidence and location_evidence.get('gps_coordinates'):
                report.append("LOCATION EVIDENCE")
                report.append("-" * 40)
                
                report.append(f"GPS Coordinates: {location_evidence.get('gps_coordinates', 'Unknown')}")
                
                location_name = location_evidence.get('location_name', {})
                if location_name:
                    report.append(f"Location Address: {location_name.get('full_address', 'Unknown')}")
                    report.append(f"Country: {location_name.get('country', 'Unknown')}")
                    report.append(f"State/Region: {location_name.get('state', 'Unknown')}")
                    report.append(f"City: {location_name.get('city', 'Unknown')}")
                
                accuracy = location_evidence.get('accuracy', {})
                if accuracy:
                    report.append(f"Location Accuracy: {accuracy.get('estimated_accuracy', 'Unknown')}")
                
                report.append(f"GPS Timestamp: {location_evidence.get('timestamp', 'Unknown')}")
                report.append("")
            
            # Chain of Custody
            chain_of_custody = evidence_chain.get('chain_of_custody', [])
            if chain_of_custody:
                report.append("CHAIN OF CUSTODY")
                report.append("-" * 40)
                
                for entry in chain_of_custody:
                    report.append(f"[{entry.get('timestamp', 'Unknown')}]")
                    report.append(f"Action: {entry.get('action', 'Unknown')}")
                    report.append(f"Handler: {entry.get('handler', 'Unknown')}")
                    report.append(f"Location: {entry.get('location', 'Unknown')}")
                    report.append(f"Description: {entry.get('description', 'Unknown')}")
                    report.append("")
            
            # Legal Metadata
            legal_metadata = evidence_chain.get('legal_metadata', {})
            if legal_metadata:
                report.append("LEGAL METADATA")
                report.append("-" * 40)
                
                for key, value in legal_metadata.items():
                    formatted_key = key.replace('_', ' ').title()
                    report.append(f"{formatted_key}: {value}")
                
                report.append("")
            
            # Recommendations
            report.append("INVESTIGATIVE RECOMMENDATIONS")
            report.append("-" * 40)
            
            if tampering_score >= 7:
                report.append("🔴 IMMEDIATE ACTIONS REQUIRED:")
                report.append("• Secure all related digital evidence")
                report.append("• Interview device owners/users")
                report.append("• Obtain device forensic examination warrants")
                report.append("• Cross-reference with location data")
                report.append("• Consult with digital forensics expert")
            elif tampering_score >= 4:
                report.append("🟡 RECOMMENDED ACTIONS:")
                report.append("• Verify device ownership and access")
                report.append("• Collect additional evidence samples")
                report.append("• Document chain of custody thoroughly")
                report.append("• Consider expert testimony preparation")
            else:
                report.append("🟢 STANDARD PROCEDURES:")
                report.append("• Maintain evidence integrity")
                report.append("• Document findings for case file")
                report.append("• Monitor for additional evidence")
            
            report.append("")
            report.append("=" * 80)
            report.append("END OF REPORT")
            report.append("=" * 80)
            
            return "\n".join(report)
            
        except Exception as e:
            return f"Investigation report generation failed: {str(e)}"