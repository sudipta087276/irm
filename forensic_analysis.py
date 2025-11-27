"""
Advanced Forensic Analysis Module for Image Watermark & Recovery System
Comprehensive digital forensics toolkit with EXIF analysis, noise patterns,
compression artifacts, and statistical forensics.
"""

import cv2
import numpy as np
import pandas as pd
from PIL import Image, ExifTags
import matplotlib.pyplot as plt
from scipy import stats, fft
from scipy.ndimage import gaussian_filter, sobel, laplace
import io
import hashlib
from datetime import datetime
import json
from typing import Dict, List, Tuple, Optional
import warnings

class AdvancedForensicAnalyzer:
    """Advanced forensic analysis toolkit for digital image forensics"""
    
    def __init__(self):
        self.analysis_results = {}
        self.chain_of_custody = []
        
    def extract_exif_metadata(self, image_path: str) -> Dict:
        """Extract comprehensive EXIF metadata and camera information"""
        try:
            with Image.open(image_path) as img:
                exif_data = {}
                if hasattr(img, '_getexif') and img._getexif() is not None:
                    exif = img._getexif()
                    for tag_id, value in exif.items():
                        tag = ExifTags.TAGS.get(tag_id, tag_id)
                        exif_data[tag] = str(value)
                
                # Additional metadata
                exif_data['format'] = img.format
                exif_data['mode'] = img.mode
                exif_data['size'] = img.size
                exif_data['has_transparency'] = img.mode in ('RGBA', 'LA') or 'transparency' in img.info
                
                return exif_data
        except Exception as e:
            return {"error": f"EXIF extraction failed: {str(e)}"}
    
    def calculate_image_hash(self, image: np.ndarray) -> Dict[str, str]:
        """Calculate multiple cryptographic hashes for image integrity verification"""
        try:
            # Convert to bytes
            img_bytes = image.tobytes()
            
            hashes = {
                "md5": hashlib.md5(img_bytes).hexdigest(),
                "sha1": hashlib.sha1(img_bytes).hexdigest(),
                "sha256": hashlib.sha256(img_bytes).hexdigest(),
                "perceptual_hash": self._calculate_perceptual_hash(image)
            }
            return hashes
        except Exception as e:
            return {"error": f"Hash calculation failed: {str(e)}"}
    
    def _calculate_perceptual_hash(self, image: np.ndarray, hash_size: int = 8) -> str:
        """Calculate perceptual hash for similarity detection"""
        try:
            # Convert to grayscale and resize
            if len(image.shape) == 3:
                gray = cv2.cvtColor(image, cv2.COLOR_RGB2GRAY)
            else:
                gray = image
            
            resized = cv2.resize(gray, (hash_size + 1, hash_size))
            
            # Calculate differences
            diff = resized[:, 1:] > resized[:, :-1]
            
            # Convert to hash string
            return ''.join(str(b) for b in diff.flatten())
        except Exception as e:
            return f"perceptual_hash_error: {str(e)}"
    
    def analyze_noise_patterns(self, image: np.ndarray) -> Dict:
        """Comprehensive noise pattern analysis for tampering detection"""
        try:
            if len(image.shape) == 3:
                gray = cv2.cvtColor(image, cv2.COLOR_RGB2GRAY)
            else:
                gray = image
            
            # Multiple noise detection methods
            noise_analysis = {
                "gaussian_noise": self._detect_gaussian_noise(gray),
                "salt_pepper_noise": self._detect_salt_pepper_noise(gray),
                "compression_artifacts": self._detect_jpeg_artifacts(gray),
                "median_filter_traces": self._detect_median_filter(gray),
                "noise_uniformity": self._analyze_noise_uniformity(gray)
            }
            
            return noise_analysis
        except Exception as e:
            return {"error": f"Noise analysis failed: {str(e)}"}
    
    def _detect_gaussian_noise(self, gray_image: np.ndarray) -> Dict:
        """Detect Gaussian noise characteristics"""
        try:
            # Use Laplacian of Gaussian
            log_noise = laplace(gray_image.astype(float))
            
            # Statistical analysis
            mean_noise = np.mean(log_noise)
            std_noise = np.std(log_noise)
            kurtosis = stats.kurtosis(log_noise.flatten())
            skewness = stats.skew(log_noise.flatten())
            
            # Signal-to-noise ratio estimation
            snr = np.std(gray_image) / (std_noise + 1e-10)
            
            return {
                "mean": float(mean_noise),
                "std": float(std_noise),
                "kurtosis": float(kurtosis),
                "skewness": float(skewness),
                "snr": float(snr),
                "gaussian_likelihood": self._assess_gaussian_distribution(log_noise)
            }
        except Exception as e:
            return {"error": f"Gaussian noise detection failed: {str(e)}"}
    
    def _detect_salt_pepper_noise(self, gray_image: np.ndarray) -> Dict:
        """Detect salt and pepper noise characteristics"""
        try:
            # Find extreme values
            min_val, max_val = np.percentile(gray_image, [1, 99])
            
            # Count pixels at extremes
            salt_pixels = np.sum(gray_image >= max_val - 5)
            pepper_pixels = np.sum(gray_image <= min_val + 5)
            
            total_pixels = gray_image.size
            salt_ratio = salt_pixels / total_pixels
            pepper_ratio = pepper_pixels / total_pixels
            
            # Detect using median filter test
            median_filtered = cv2.medianBlur(gray_image, 3)
            diff = np.abs(gray_image.astype(float) - median_filtered.astype(float))
            impulsive_pixels = np.sum(diff > 50)
            
            return {
                "salt_ratio": float(salt_ratio),
                "pepper_ratio": float(pepper_ratio),
                "impulsive_noise_ratio": float(impulsive_pixels / total_pixels),
                "likely_salt_pepper": bool(salt_ratio > 0.001 or pepper_ratio > 0.001)
            }
        except Exception as e:
            return {"error": f"Salt-pepper detection failed: {str(e)}"}
    
    def _detect_jpeg_artifacts(self, gray_image: np.ndarray) -> Dict:
        """Detect JPEG compression artifacts"""
        try:
            # Block artifact detection (8x8 JPEG blocks)
            h, w = gray_image.shape
            block_size = 8
            
            # Calculate block boundaries
            horizontal_edges = []
            vertical_edges = []
            
            # Detect blocking artifacts
            for y in range(block_size, h - block_size, block_size):
                row_diff = np.abs(gray_image[y, :] - gray_image[y-1, :])
                horizontal_edges.append(np.mean(row_diff))
            
            for x in range(block_size, w - block_size, block_size):
                col_diff = np.abs(gray_image[:, x] - gray_image[:, x-1])
                vertical_edges.append(np.mean(col_diff))
            
            # DCT coefficient analysis
            dct_artifacts = self._analyze_dct_coefficients(gray_image)
            
            return {
                "horizontal_blocking": float(np.mean(horizontal_edges)) if horizontal_edges else 0,
                "vertical_blocking": float(np.mean(vertical_edges)) if vertical_edges else 0,
                "blocking_severity": float(np.std(horizontal_edges + vertical_edges)),
                "dct_analysis": dct_artifacts,
                "likely_jpeg": bool(np.std(horizontal_edges + vertical_edges) > 2.0)
            }
        except Exception as e:
            return {"error": f"JPEG artifact detection failed: {str(e)}"}
    
    def _analyze_dct_coefficients(self, gray_image: np.ndarray) -> Dict:
        """Analyze DCT coefficients for compression artifacts"""
        try:
            # Sample 8x8 blocks
            h, w = gray_image.shape
            block_size = 8
            
            dct_coeffs = []
            for y in range(0, h - block_size + 1, block_size):
                for x in range(0, w - block_size + 1, block_size):
                    block = gray_image[y:y+block_size, x:x+block_size]
                    dct_block = fft.dctn(block, norm='ortho')
                    dct_coeffs.append(np.abs(dct_block.flatten()))
            
            if dct_coeffs:
                dct_coeffs = np.array(dct_coeffs)
                
                # Analyze coefficient distribution
                ac_coeffs = dct_coeffs[:, 1:]  # Exclude DC coefficient
                
                return {
                    "mean_ac_energy": float(np.mean(ac_coeffs)),
                    "ac_energy_std": float(np.std(ac_coeffs)),
                    "quantization_likelihood": float(np.std(dct_coeffs[:, 1:9]))  # Low-frequency AC coeffs
                }
            else:
                return {"error": "No DCT blocks analyzed"}
        except Exception as e:
            return {"error": f"DCT analysis failed: {str(e)}"}
    
    def _detect_median_filter(self, gray_image: np.ndarray) -> Dict:
        """Detect median filter traces (indicating tampering)"""
        try:
            # Apply different median filters
            median_3 = cv2.medianBlur(gray_image, 3)
            median_5 = cv2.medianBlur(gray_image, 5)
            
            # Calculate differences
            diff_3 = np.abs(gray_image.astype(float) - median_3.astype(float))
            diff_5 = np.abs(gray_image.astype(float) - median_5.astype(float))
            
            # Statistical analysis
            mean_diff_3 = np.mean(diff_3)
            mean_diff_5 = np.mean(diff_5)
            
            # Detect median filter traces
            # Median filtered images have characteristic pixel value distributions
            pixel_values = np.unique(gray_image)
            value_counts = [np.sum(gray_image == val) for val in pixel_values]
            
            # Calculate smoothness of histogram
            hist_smoothness = np.std(np.diff(value_counts))
            
            return {
                "median_filter_3_diff": float(mean_diff_3),
                "median_filter_5_diff": float(mean_diff_5),
                "histogram_smoothness": float(hist_smoothness),
                "likely_median_filtered": bool(hist_smoothness < 10 and mean_diff_3 < 5)
            }
        except Exception as e:
            return {"error": f"Median filter detection failed: {str(e)}"}
    
    def _analyze_noise_uniformity(self, gray_image: np.ndarray) -> Dict:
        """Analyze noise uniformity across image regions"""
        try:
            h, w = gray_image.shape
            
            # Divide into regions
            regions = 4
            region_h, region_w = h // regions, w // regions
            
            region_stats = []
            for i in range(regions):
                for j in range(regions):
                    region = gray_image[i*region_h:(i+1)*region_h, j*region_w:(j+1)*region_w]
                    
                    # Calculate local noise statistics
                    local_noise = laplace(region.astype(float))
                    stats_dict = {
                        "region": (i, j),
                        "mean_noise": float(np.mean(local_noise)),
                        "std_noise": float(np.std(local_noise)),
                        "noise_energy": float(np.mean(local_noise**2))
                    }
                    region_stats.append(stats_dict)
            
            # Calculate uniformity metrics
            noise_means = [s["mean_noise"] for s in region_stats]
            noise_stds = [s["std_noise"] for s in region_stats]
            
            return {
                "region_stats": region_stats,
                "noise_uniformity": float(np.std(noise_means)),
                "std_uniformity": float(np.std(noise_stds)),
                "likely_uniform_noise": bool(np.std(noise_means) < 2.0)
            }
        except Exception as e:
            return {"error": f"Noise uniformity analysis failed: {str(e)}"}
    
    def perform_error_level_analysis(self, image: np.ndarray, quality: int = 95) -> Dict:
        """Perform Error Level Analysis (ELA) for tampering detection"""
        try:
            # Convert to PIL format for JPEG compression
            if len(image.shape) == 3:
                pil_image = Image.fromarray(image.astype('uint8'), 'RGB')
            else:
                pil_image = Image.fromarray(image.astype('uint8'), 'L')
            
            # Save as JPEG with specified quality
            buffer = io.BytesIO()
            pil_image.save(buffer, format='JPEG', quality=quality)
            buffer.seek(0)
            
            # Load back and convert to numpy
            compressed_img = Image.open(buffer)
            compressed_array = np.array(compressed_img)
            
            if len(image.shape) == 3 and len(compressed_array.shape) == 2:
                compressed_array = cv2.cvtColor(compressed_array, cv2.COLOR_GRAY2RGB)
            
            # Calculate error level
            if len(image.shape) == 3:
                error_level = np.abs(image.astype(float) - compressed_array.astype(float))
            else:
                error_level = np.abs(image.astype(float) - compressed_array.astype(float))
            
            # Normalize error level
            error_normalized = (error_level - error_level.min()) / (error_level.max() - error_level.min() + 1e-10)
            
            # Statistical analysis
            mean_error = np.mean(error_level)
            std_error = np.std(error_level)
            
            # Detect suspicious regions (high error areas)
            threshold = mean_error + 2 * std_error
            suspicious_mask = error_level > threshold
            
            return {
                "error_level_map": error_normalized,
                "mean_error": float(mean_error),
                "std_error": float(std_error),
                "suspicious_regions": float(np.sum(suspicious_mask) / suspicious_mask.size),
                "ela_score": float(std_error / (mean_error + 1e-10)),
                "likely_tampered": bool(std_error / (mean_error + 1e-10) > 1.5)
            }
        except Exception as e:
            return {"error": f"ELA failed: {str(e)}"}
    
    def analyze_histogram_anomalies(self, image: np.ndarray) -> Dict:
        """Analyze histogram for signs of manipulation"""
        try:
            if len(image.shape) == 3:
                # Analyze each channel separately
                channels = ['R', 'G', 'B']
                histogram_analysis = {}
                
                for i, channel in enumerate(channels):
                    channel_hist = cv2.calcHist([image], [i], None, [256], [0, 256])
                    channel_hist = channel_hist.flatten()
                    
                    histogram_analysis[channel] = self._analyze_single_histogram(channel_hist)
                
                # Combined analysis
                combined_hist = cv2.calcHist([image], [0, 1, 2], None, [256, 256, 256], [0, 256, 0, 256, 0, 256])
                
                return {
                    "channel_analysis": histogram_analysis,
                    "combined_histogram": combined_hist,
                    "overall_anomaly_score": np.mean([hist["anomaly_score"] for hist in histogram_analysis.values()])
                }
            else:
                # Grayscale analysis
                hist = cv2.calcHist([image], [0], None, [256], [0, 256])
                hist = hist.flatten()
                return {"grayscale": self._analyze_single_histogram(hist)}
        except Exception as e:
            return {"error": f"Histogram analysis failed: {str(e)}"}
    
    def _analyze_single_histogram(self, histogram: np.ndarray) -> Dict:
        """Analyze a single histogram for anomalies"""
        try:
            # Smooth the histogram
            smoothed = gaussian_filter(histogram, sigma=2)
            
            # Detect peaks and valleys
            peaks, _ = self._find_peaks(histogram)
            valleys, _ = self._find_valleys(histogram)
            
            # Calculate statistics
            total_pixels = np.sum(histogram)
            
            # Detect histogram anomalies
            gaps = self._detect_histogram_gaps(histogram)
            spikes = self._detect_histogram_spikes(histogram)
            
            # Calculate smoothness
            gradient = np.gradient(smoothed)
            smoothness = np.std(gradient)
            
            return {
                "num_peaks": len(peaks),
                "num_valleys": len(valleys),
                "gaps_detected": gaps,
                "spikes_detected": spikes,
                "smoothness": float(smoothness),
                "anomaly_score": float(len(gaps) + len(spikes) + (smoothness > 10)),
                "likely_manipulated": bool(len(gaps) > 2 or len(spikes) > 2 or smoothness > 15)
            }
        except Exception as e:
            return {"error": f"Single histogram analysis failed: {str(e)}"}
    
    def _find_peaks(self, data: np.ndarray) -> Tuple[List[int], List[float]]:
        """Find peaks in data"""
        peaks = []
        values = []
        for i in range(1, len(data) - 1):
            if data[i] > data[i-1] and data[i] > data[i+1] and data[i] > np.mean(data):
                peaks.append(i)
                values.append(data[i])
        return peaks, values
    
    def _find_valleys(self, data: np.ndarray) -> Tuple[List[int], List[float]]:
        """Find valleys in data"""
        valleys = []
        values = []
        for i in range(1, len(data) - 1):
            if data[i] < data[i-1] and data[i] < data[i+1] and data[i] < np.mean(data):
                valleys.append(i)
                values.append(data[i])
        return valleys, values
    
    def _detect_histogram_gaps(self, histogram: np.ndarray) -> List[int]:
        """Detect gaps in histogram (zero or near-zero values)"""
        gaps = []
        threshold = np.max(histogram) * 0.001  # 0.1% of max
        
        for i in range(len(histogram)):
            if histogram[i] < threshold:
                gaps.append(i)
        
        return gaps
    
    def _detect_histogram_spikes(self, histogram: np.ndarray) -> List[int]:
        """Detect spikes in histogram (sudden high values)"""
        spikes = []
        smoothed = gaussian_filter(histogram, sigma=1)
        
        for i in range(1, len(histogram) - 1):
            if histogram[i] > smoothed[i] * 2 and histogram[i] > np.mean(histogram) * 3:
                spikes.append(i)
        
        return spikes
    
    def perform_comprehensive_forensics(self, image: np.ndarray, image_path: Optional[str] = None) -> Dict:
        """Perform comprehensive forensic analysis"""
        try:
            results = {
                "timestamp": datetime.now().isoformat(),
                "image_shape": image.shape,
                "image_hash": self.calculate_image_hash(image),
                "noise_analysis": self.analyze_noise_patterns(image),
                "error_level_analysis": self.perform_error_level_analysis(image),
                "histogram_analysis": self.analyze_histogram_anomalies(image),
                "forensic_score": 0.0,
                "tampering_likelihood": "unknown"
            }
            
            # Add EXIF data if path provided
            if image_path:
                results["exif_metadata"] = self.extract_exif_metadata(image_path)
            
            # Calculate overall forensic score
            results["forensic_score"] = self._calculate_forensic_score(results)
            results["tampering_likelihood"] = self._assess_tampering_likelihood(results)
            
            return results
        except Exception as e:
            return {"error": f"Comprehensive forensics failed: {str(e)}"}
    
    def _calculate_forensic_score(self, results: Dict) -> float:
        """Calculate overall forensic score based on various indicators"""
        score = 0.0
        max_score = 10.0
        
        # Noise analysis scoring
        if "noise_analysis" in results and "error" not in results["noise_analysis"]:
            noise = results["noise_analysis"]
            
            # Check for suspicious noise patterns
            if "gaussian_noise" in noise and noise["gaussian_noise"].get("snr", 0) < 10:
                score += 2.0
            
            if "compression_artifacts" in noise and noise["compression_artifacts"].get("likely_jpeg", False):
                score += 1.0
            
            if "median_filter_traces" in noise and noise["median_filter_traces"].get("likely_median_filtered", False):
                score += 2.5
            
            if "salt_pepper_noise" in noise and noise["salt_pepper_noise"].get("likely_salt_pepper", False):
                score += 1.5
        
        # ELA scoring
        if "error_level_analysis" in results and "error" not in results["error_level_analysis"]:
            ela = results["error_level_analysis"]
            if ela.get("likely_tampered", False):
                score += 3.0
            score += min(ela.get("ela_score", 0), 2.0)
        
        # Histogram analysis scoring
        if "histogram_analysis" in results and "error" not in results["histogram_analysis"]:
            hist = results["histogram_analysis"]
            anomaly_score = hist.get("overall_anomaly_score", 0)
            score += min(anomaly_score, 2.0)
        
        return min(score, max_score)
    
    def _assess_tampering_likelihood(self, results: Dict) -> str:
        """Assess overall tampering likelihood"""
        forensic_score = results.get("forensic_score", 0)
        
        if forensic_score >= 7.0:
            return "High likelihood of tampering"
        elif forensic_score >= 4.0:
            return "Moderate likelihood of tampering"
        elif forensic_score >= 2.0:
            return "Low likelihood of tampering"
        else:
            return "No significant tampering indicators"
    
    def generate_forensic_report(self, results: Dict) -> str:
        """Generate comprehensive forensic report"""
        try:
            report = []
            report.append("=" * 60)
            report.append("DIGITAL FORENSIC ANALYSIS REPORT")
            report.append("=" * 60)
            report.append(f"Analysis Date: {results.get('timestamp', 'Unknown')}")
            report.append(f"Image Dimensions: {results.get('image_shape', 'Unknown')}")
            report.append(f"Forensic Score: {results.get('forensic_score', 0):.2f}/10")
            report.append(f"Tampering Assessment: {results.get('tampering_likelihood', 'Unknown')}")
            report.append("")
            
            # Hash verification
            if "image_hash" in results and "error" not in results["image_hash"]:
                report.append("IMAGE INTEGRITY VERIFICATION:")
                hashes = results["image_hash"]
                report.append(f"  MD5: {hashes.get('md5', 'N/A')}")
                report.append(f"  SHA1: {hashes.get('sha1', 'N/A')}")
                report.append(f"  SHA256: {hashes.get('sha256', 'N/A')}")
                report.append(f"  Perceptual Hash: {hashes.get('perceptual_hash', 'N/A')[:20]}...")
                report.append("")
            
            # Noise analysis
            if "noise_analysis" in results and "error" not in results["noise_analysis"]:
                report.append("NOISE PATTERN ANALYSIS:")
                noise = results["noise_analysis"]
                
                if "gaussian_noise" in noise:
                    gn = noise["gaussian_noise"]
                    report.append(f"  Gaussian Noise - SNR: {gn.get('snr', 0):.2f}")
                    report.append(f"  Gaussian Likelihood: {gn.get('gaussian_likelihood', 0):.3f}")
                
                if "compression_artifacts" in noise:
                    ca = noise["compression_artifacts"]
                    report.append(f"  JPEG Artifacts Detected: {ca.get('likely_jpeg', False)}")
                    report.append(f"  Blocking Severity: {ca.get('blocking_severity', 0):.2f}")
                
                if "median_filter_traces" in noise:
                    mf = noise["median_filter_traces"]
                    report.append(f"  Median Filter Traces: {mf.get('likely_median_filtered', False)}")
                
                if "salt_pepper_noise" in noise:
                    sp = noise["salt_pepper_noise"]
                    report.append(f"  Salt & Pepper Noise: {sp.get('likely_salt_pepper', False)}")
                
                report.append("")
            
            # ELA results
            if "error_level_analysis" in results and "error" not in results["error_level_analysis"]:
                report.append("ERROR LEVEL ANALYSIS (ELA):")
                ela = results["error_level_analysis"]
                report.append(f"  ELA Score: {ela.get('ela_score', 0):.3f}")
                report.append(f"  Suspicious Regions: {ela.get('suspicious_regions', 0)*100:.2f}%")
                report.append(f"  Tampering Indicated: {ela.get('likely_tampered', False)}")
                report.append("")
            
            # Histogram analysis
            if "histogram_analysis" in results and "error" not in results["histogram_analysis"]:
                report.append("HISTOGRAM ANOMALY ANALYSIS:")
                hist = results["histogram_analysis"]
                report.append(f"  Overall Anomaly Score: {hist.get('overall_anomaly_score', 0):.2f}")
                
                if "channel_analysis" in hist:
                    for channel, analysis in hist["channel_analysis"].items():
                        if "error" not in analysis:
                            report.append(f"  Channel {channel}: {analysis.get('likely_manipulated', False)}")
                report.append("")
            
            # Recommendations
            report.append("FORENSIC RECOMMENDATIONS:")
            if results.get("forensic_score", 0) >= 7.0:
                report.append("  ⚠️  HIGH PRIORITY: Image shows strong tampering indicators.")
                report.append("     Recommend detailed manual review and additional forensic tests.")
            elif results.get("forensic_score", 0) >= 4.0:
                report.append("  ⚡ MODERATE: Image shows moderate tampering indicators.")
                report.append("     Recommend supplementary analysis and expert review.")
            elif results.get("forensic_score", 0) >= 2.0:
                report.append("  ℹ️  LOW: Image shows minor tampering indicators.")
                report.append("     Monitor and consider additional verification.")
            else:
                report.append("  ✅ CLEAR: No significant tampering indicators detected.")
                report.append("     Image appears authentic based on automated analysis.")
            
            report.append("")
            report.append("=" * 60)
            report.append("End of Report")
            report.append("=" * 60)
            
            return "\n".join(report)
        except Exception as e:
            return f"Report generation failed: {str(e)}"
    
    def _assess_gaussian_distribution(self, data: np.ndarray) -> float:
        """Assess how well data fits a Gaussian distribution"""
        try:
            # Normalize data
            normalized = (data - np.mean(data)) / (np.std(data) + 1e-10)
            
            # Perform normality tests
            _, p_value_shapiro = stats.shapiro(normalized.flatten()[:5000])  # Limit for performance
            
            # Calculate kurtosis and skewness
            kurtosis = abs(stats.kurtosis(normalized.flatten()))
            skewness = abs(stats.skew(normalized.flatten()))
            
            # Combined score (0-1, where 1 is perfectly Gaussian)
            gaussian_score = max(0, 1 - (kurtosis + skewness + (1 - p_value_shapiro)) / 3)
            
            return float(gaussian_score)
        except Exception as e:
            return 0.0