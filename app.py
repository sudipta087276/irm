import streamlit as st
import numpy as np
import cv2
import os
import random
import string
from datetime import datetime
import pandas as pd
from skimage.metrics import peak_signal_noise_ratio as psnr, structural_similarity as ssim
import matplotlib.pyplot as plt
import io
from scipy.ndimage import gaussian_laplace
from forensic_analysis import AdvancedForensicAnalyzer
from enhanced_forensic_analysis_simple import EnhancedForensicAnalyzerSimple as EnhancedForensicAnalyzer
import seaborn as sns

# ---- Directories ----
WM_DIR = "data/Watermarked"
RCV_DIR = "data/Recovered"
FORENSIC_REPORTS_DIR = "data/ForensicReports"
os.makedirs(WM_DIR, exist_ok=True)
os.makedirs(RCV_DIR, exist_ok=True)
os.makedirs(FORENSIC_REPORTS_DIR, exist_ok=True)

# Initialize forensic analyzers
forensic_analyzer = AdvancedForensicAnalyzer()
enhanced_forensic_analyzer = EnhancedForensicAnalyzer()

def random_code(length=20):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def embed_watermark_color(img, watermark, logo=None, strength="Normal"):
    h, w, c = img.shape
    wm_img = img.copy()
    # Watermark text: LSB, 2 bits per channel, distributed
    wm_bits = ''.join(format(ord(x), '08b') for x in watermark)
    idx = 0
    step = {"Invisible": 1, "Normal": 2, "Strong": 4}[strength]
    for y in range(0, h, step):
        for x in range(0, w, step):
            for ch in range(3):
                px = wm_img[y, x, ch]
                if idx + 2 <= len(wm_bits):
                    bits = wm_bits[idx:idx+2]
                    px = (px & 0xFC) | (int(bits[0]) << 1) | int(bits[1])
                    wm_img[y, x, ch] = px
                    idx += 2
                if idx >= len(wm_bits): idx = 0
    # Logo watermark (if present)
    if logo is not None:
        logo = cv2.resize(logo, (w//6, h//6))
        y_offset = h - logo.shape[0] - 10
        x_offset = w - logo.shape[1] - 10
        overlay = wm_img[y_offset:y_offset+logo.shape[0], x_offset:x_offset+logo.shape[1]]
        alpha = 0.33
        wm_img[y_offset:y_offset+logo.shape[0], x_offset:x_offset+logo.shape[1]] = cv2.addWeighted(overlay, 1-alpha, logo, alpha, 0)
    return wm_img

def extract_watermark_color(img, length=20):
    h, w, c = img.shape
    bits = ''
    for y in range(0, h, 2):
        for x in range(0, w, 2):
            for ch in range(3):
                px = img[y, x, ch]
                bits += str((px >> 1) & 1)
                bits += str(px & 1)
                if len(bits) >= length*8:
                    code = ''.join([chr(int(bits[k:k+8], 2)) for k in range(0, length*8, 8)])
                    if all(c in string.ascii_letters + string.digits for c in code):
                        return code
                    else:
                        return None
    return None

def block_tamper_map(orig, test, block=2, thresh=15):
    import math
    h, w, _ = orig.shape
    mask = np.zeros((h, w), dtype=np.uint8)
    # Use ceil to ensure we cover all edge pixels
    h_blocks = math.ceil(h / block)
    w_blocks = math.ceil(w / block)
    heatmap = np.zeros((h_blocks, w_blocks))
    report = []
    
    # Iterate by blocks to avoid off-by-one errors
    for by in range(h_blocks):
        for bx in range(w_blocks):
            # Calculate actual pixel coordinates for this block
            y0 = by * block
            x0 = bx * block
            y1 = min(y0 + block, h)  # Clamp to image bounds
            x1 = min(x0 + block, w)  # Clamp to image bounds
            
            # Extract the actual block (may be smaller at edges)
            bo = orig[y0:y1, x0:x1, :]
            bt = test[y0:y1, x0:x1, :]
            diff = np.abs(bo.astype(np.int16) - bt.astype(np.int16))
            v = np.max(diff)
            tampered = v > thresh
            
            if tampered:
                mask[y0:y1, x0:x1] = 255
            
            heatmap[by, bx] = v
            report.append({
                "block_y": by, "block_x": bx,
                "tampered": int(tampered), "max_diff": float(v)
            })
    tamper_pct = np.mean(mask > 0) * 100
    color_mask = cv2.cvtColor(mask, cv2.COLOR_GRAY2RGB)
    color_mask[mask > 0] = [255, 69, 0]
    return tamper_pct, color_mask, mask, heatmap, pd.DataFrame(report)

def recover_blocks(orig, test, mask, block=2):
    h, w, _ = orig.shape
    rec = test.copy()
    for y in range(0, h, block):
        for x in range(0, w, block):
            if np.any(mask[y:y+block, x:x+block] > 0):
                rec[y:y+block, x:x+block, :] = orig[y:y+block, x:x+block, :]
    return rec

def get_metrics(orig, test):
    scores = {}
    try:
        # Calculate MSE first to check for identical images
        mse = np.mean((orig.astype(np.float32) - test.astype(np.float32)) ** 2)
        
        if mse == 0:
            # Images are identical, PSNR is theoretically infinite
            scores["PSNR"] = float('inf')
        else:
            scores["PSNR"] = float(psnr(orig, test, data_range=255))
            
        scores["SSIM"] = float(ssim(orig, test, channel_axis=2, data_range=255))
        norm_corr = float(np.corrcoef(orig.flatten(), test.flatten())[0, 1])
        scores["NC"] = norm_corr
    except Exception as e:
        scores["PSNR"] = 0.0
        scores["SSIM"] = 0.0
        scores["NC"] = 0.0
        scores["error"] = str(e)
    return scores

# Advanced forensic analysis functions
def image_histogram(img):
    gray = cv2.cvtColor(img, cv2.COLOR_RGB2GRAY)
    hist = cv2.calcHist([gray], [0], None, [256], [0, 256])
    hist = hist.flatten()
    return hist / hist.sum()

def noise_map(img):
    gray = cv2.cvtColor(img, cv2.COLOR_RGB2GRAY)
    noise = gaussian_laplace(gray.astype(float), sigma=1)
    return np.abs(noise)

def advanced_forensic_analysis(image, image_path=None):
    """Perform comprehensive forensic analysis using AdvancedForensicAnalyzer"""
    try:
        results = forensic_analyzer.perform_comprehensive_forensics(image, image_path)
        return results
    except Exception as e:
        return {"error": f"Forensic analysis failed: {str(e)}"}

def enhanced_device_forensic_analysis(image_path):
    """Perform enhanced device/GPS forensic analysis using EnhancedForensicAnalyzer"""
    try:
        results = enhanced_forensic_analyzer.extract_comprehensive_metadata(image_path)
        return results
    except Exception as e:
        return {"error": f"Enhanced forensic analysis failed: {str(e)}"}

def detect_tampering_device(original_path, tampered_path):
    """Detect which device was used for tampering by comparing metadata"""
    try:
        original_metadata = enhanced_forensic_analyzer.extract_comprehensive_metadata(original_path)
        tampered_metadata = enhanced_forensic_analyzer.extract_comprehensive_metadata(tampered_path)
        
        device_analysis = enhanced_forensic_analyzer.detect_tampering_device(original_metadata, tampered_metadata)
        return device_analysis
    except Exception as e:
        return {"error": f"Device tampering detection failed: {str(e)}"}

def create_evidence_chain(image_path, analysis_results):
    """Create forensic evidence chain for law enforcement"""
    try:
        evidence_chain = enhanced_forensic_analyzer.create_forensic_evidence_chain(image_path, analysis_results)
        return evidence_chain
    except Exception as e:
        return {"error": f"Evidence chain creation failed: {str(e)}"}

def generate_investigation_report(evidence_chain, analysis_results):
    """Generate comprehensive investigation report"""
    try:
        report = enhanced_forensic_analyzer.generate_investigation_report(evidence_chain, analysis_results)
        return report
    except Exception as e:
        return f"Investigation report generation failed: {str(e)}"

def generate_forensic_visualizations(results, image):
    """Generate advanced forensic visualizations"""
    try:
        visualizations = {}
        
        # Error Level Analysis visualization
        if "error_level_analysis" in results and "error" not in results["error_level_analysis"]:
            ela_data = results["error_level_analysis"]
            if "error_level_map" in ela_data:
                visualizations["ela_map"] = ela_data["error_level_map"]
        
        # Noise pattern visualization
        if "noise_analysis" in results and "error" not in results["noise_analysis"]:
            noise_data = results["noise_analysis"]
            if "region_stats" in noise_data.get("noise_uniformity", {}):
                # Create noise uniformity heatmap
                region_stats = noise_data["noise_uniformity"]["region_stats"]
                grid_size = int(np.sqrt(len(region_stats)))
                if grid_size > 0:
                    noise_grid = np.zeros((grid_size, grid_size))
                    for i, stat in enumerate(region_stats):
                        row, col = stat["region"]
                        if row < grid_size and col < grid_size:
                            noise_grid[row, col] = stat["noise_energy"]
                    visualizations["noise_uniformity"] = noise_grid
        
        return visualizations
    except Exception as e:
        return {"error": f"Visualization generation failed: {str(e)}"}

def create_forensic_dashboard(results):
    """Create comprehensive forensic dashboard"""
    try:
        dashboard_data = {
            "forensic_score": results.get("forensic_score", 0),
            "tampering_likelihood": results.get("tampering_likelihood", "Unknown"),
            "key_indicators": []
        }
        
        # Analyze key indicators
        if "noise_analysis" in results and "error" not in results["noise_analysis"]:
            noise = results["noise_analysis"]
            
            if noise.get("median_filter_traces", {}).get("likely_median_filtered", False):
                dashboard_data["key_indicators"].append("Median filter traces detected")
            
            if noise.get("compression_artifacts", {}).get("likely_jpeg", False):
                dashboard_data["key_indicators"].append("JPEG compression artifacts")
            
            if noise.get("salt_pepper_noise", {}).get("likely_salt_pepper", False):
                dashboard_data["key_indicators"].append("Salt & pepper noise detected")
        
        if "error_level_analysis" in results and "error" not in results["error_level_analysis"]:
            ela = results["error_level_analysis"]
            if ela.get("likely_tampered", False):
                dashboard_data["key_indicators"].append("Error level analysis indicates tampering")
        
        if "histogram_analysis" in results and "error" not in results["histogram_analysis"]:
            hist = results["histogram_analysis"]
            if hist.get("overall_anomaly_score", 0) > 2.0:
                dashboard_data["key_indicators"].append("Histogram anomalies detected")
        
        return dashboard_data
    except Exception as e:
        return {"error": f"Dashboard creation failed: {str(e)}"}

def copy_move_detection(img, block=8, stride=4, threshold=0.99):
    gray = cv2.cvtColor(img, cv2.COLOR_RGB2GRAY)
    h, w = gray.shape
    blocks = []
    locs = []
    for y in range(0, h-block+1, stride):
        for x in range(0, w-block+1, stride):
            b = gray[y:y+block, x:x+block].flatten()
            blocks.append(b)
            locs.append((y, x))
    blocks = np.array(blocks)
    # Normalize blocks
    blocks = blocks - blocks.mean(axis=1, keepdims=True)
    blocks = blocks / (blocks.std(axis=1, keepdims=True) + 1e-5)
    detected = np.zeros_like(gray, dtype=np.uint8)
    # Brute force search for identical blocks
    for i in range(len(blocks)):
        sims = blocks @ blocks[i]
        sims[i] = 0
        j = np.argmax(sims)
        if sims[j] > threshold * block * block:
            y1, x1 = locs[i]
            y2, x2 = locs[j]
            detected[y1:y1+block, x1:x1+block] = 255
            detected[y2:y2+block, x2:x2+block] = 255
    return detected

# ---- Streamlit UI ----

st.set_page_config(page_title="Secure Watermark & Forensic Recovery", layout="wide")
st.title("🛡️ Secure Color Image Watermark & Forensic Recovery System")

if "history" not in st.session_state:
    st.session_state["history"] = []

tab1, tab2, tab3 = st.tabs(["Watermark Creation", "Tampering & Recovery", "Forensic & Passive Analysis"])

with tab1:
    st.header("Watermark Creation")
    uploaded = st.file_uploader("Upload Color Image", type=["png", "jpg", "jpeg", "tif"])
    custom_code = st.text_input("Enter Watermark (leave blank for random)")
    logo_up = st.file_uploader("Optional: Upload Logo as Watermark", type=["png", "jpg", "jpeg"])
    strength = st.select_slider("Watermark Strength", options=["Invisible", "Normal", "Strong"], value="Normal")
    if uploaded:
        file_bytes = np.asarray(bytearray(uploaded.read()), np.uint8)
        img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
        img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
        
        # Store in session state for other tabs
        st.session_state["original_image"] = img.copy()
        
        st.image(img, caption="Original", use_container_width=True)
        code = custom_code if custom_code else random_code()
        logo = None
        if logo_up:
            logo_bytes = np.asarray(bytearray(logo_up.read()), np.uint8)
            logo = cv2.imdecode(logo_bytes, cv2.IMREAD_COLOR)
            logo = cv2.cvtColor(logo, cv2.COLOR_BGR2RGB)
        wm_img = embed_watermark_color(img, code, logo, strength)
        
        # Store watermarked image in session state
        st.session_state["watermarked_image"] = wm_img.copy()
        
        if st.button("Preview Watermarked Image"):
            st.image(wm_img, caption="Watermarked", use_container_width=True)
            diff = cv2.absdiff(img, wm_img)
            st.image(diff, caption="Difference Image", use_container_width=True)
        if st.button("Download Watermarked Image"):
            save_path = os.path.join(WM_DIR, f"{code}.png")
            cv2.imwrite(save_path, cv2.cvtColor(wm_img, cv2.COLOR_RGB2BGR))
            _, buf = cv2.imencode('.png', cv2.cvtColor(wm_img, cv2.COLOR_RGB2BGR))
            st.download_button("Download", buf.tobytes(), f"{code}.png", "image/png")
            cert = f"Watermark: {code}\nTime: {datetime.now()}\nImage shape: {img.shape}\nEmbedder: Secure System"
            st.download_button("Certificate", cert, "watermark_certificate.txt")
            st.success("Watermarked image and certificate ready!")
            st.session_state["history"].append({"time": str(datetime.now()), "action": "created", "code": code})

with tab2:
    st.header("Tampering & Recovery")
    uploaded_wm = st.file_uploader(
        "Upload Suspected Watermarked Image", 
        type=["png", "jpg", "jpeg", "tif"], 
        key="tamper"
    )
    if uploaded_wm:
        file_bytes = np.asarray(bytearray(uploaded_wm.read()), np.uint8)
        test_img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
        test_img = cv2.cvtColor(test_img, cv2.COLOR_BGR2RGB)
        st.image(test_img, caption="Uploaded", use_container_width=True)
        code = extract_watermark_color(test_img)
        if not code:
            st.error("No valid watermark code found!")
        else:
            orig_path = os.path.join(WM_DIR, f"{code}.png")
            if not os.path.exists(orig_path):
                st.error("Original watermarked image not found!")
            else:
                orig_img = cv2.imread(orig_path)
                orig_img = cv2.cvtColor(orig_img, cv2.COLOR_BGR2RGB)
                
                # Store tampered image in session state
                st.session_state["tampered_image"] = test_img.copy()
                
                st.image([orig_img, test_img], caption=["Original", "Uploaded"], width=256)

                # --- Tamper Detection ---
                pct, color_mask, mask, heatmap, forensic_df = block_tamper_map(orig_img, test_img, block=2, thresh=15)
                st.warning(f"Tampered: {pct:.2f}% of blocks")
                st.image(color_mask, caption="Tampered Regions (Orange)", use_container_width=True)

                # --- Heatmap ---
                fig, ax = plt.subplots(figsize=(4, 4))
                ax.imshow(heatmap, cmap='jet')
                ax.axis('off')
                buf = io.BytesIO()
                fig.savefig(buf, format="png", bbox_inches='tight', pad_inches=0)
                st.image(buf.getvalue(), caption="Heatmap (Block-wise max diff)", use_container_width=True)
                plt.close(fig)
                
                # --- Recovery ---
                recovered = recover_blocks(orig_img, test_img, mask, block=2)
                st.session_state["recovered_image"] = recovered.copy()  # Store recovered image
                st.image([recovered], caption=["Recovered"], width=256)
                st.session_state["history"].append({
                    "time": str(datetime.now()), "action": "tamper_checked", "code": code, "tampered_pct": pct
                })

                # --- Forensic CSV and Metrics ---
                metrics = get_metrics(orig_img, test_img)
                rec_metrics = get_metrics(orig_img, recovered)
                st.write("Metrics vs. Uploaded:", metrics)
                st.write("Metrics vs. Recovered:", rec_metrics)
                st.dataframe(forensic_df)
                st.download_button(
                    "Download Forensic Report CSV", 
                    forensic_df.to_csv(index=False), 
                    f"forensic_report_{code}.csv", 
                    "text/csv"
                )

                if st.button("Download Recovered Image"):
                    rec_path = os.path.join(RCV_DIR, f"recovered_{code}.png")
                    cv2.imwrite(rec_path, cv2.cvtColor(recovered, cv2.COLOR_RGB2BGR))
                    _, buf = cv2.imencode('.png', cv2.cvtColor(recovered, cv2.COLOR_RGB2BGR))
                    st.download_button("Download Recovered", buf.tobytes(), f"recovered_{code}.png", "image/png")

                # ---- FORENSIC ANALYSIS GRAPHS ----
                st.markdown("## 🕵️ Forensic Analysis Graphs")

                # 1. Grayscale Histogram Comparison
                hist_orig = image_histogram(orig_img)
                hist_tamp = image_histogram(test_img)
                fig1, ax1 = plt.subplots()
                ax1.plot(hist_orig, label='Original', color='blue')
                ax1.plot(hist_tamp, label='Tampered', color='red', alpha=0.7)
                ax1.set_xlim([0, 255])
                ax1.set_xlabel("Pixel Intensity")
                ax1.set_ylabel("Frequency (normalized)")
                ax1.set_title("Histogram: Original vs Tampered")
                ax1.legend()
                st.pyplot(fig1)

                # 2. Noise Map Histogram (for tampered)
                noise_map_tampered = noise_map(test_img)
                noise_norm_tamp = (noise_map_tampered - noise_map_tampered.min()) / (np.ptp(noise_map_tampered) + 1e-9)
                fig2, ax2 = plt.subplots()
                ax2.hist(noise_norm_tamp.ravel(), bins=50, color='orange', alpha=0.7)
                ax2.set_title("Histogram of Noise Map (Tampered)")
                ax2.set_xlabel("Normalized Noise Value")
                ax2.set_ylabel("Pixel Count")
                st.pyplot(fig2)

                # 3. Blockwise Tamper Rate Bar Chart
                blockwise = forensic_df.groupby('block_y')['tampered'].mean() * 100
                fig3, ax3 = plt.subplots()
                ax3.bar(blockwise.index, blockwise.values, color='crimson')
                ax3.set_title("Blockwise Tamper Rate (%)")
                ax3.set_xlabel("Block Row")
                ax3.set_ylabel("Tampered (%)")
                st.pyplot(fig3)

                # 4. Histogram of Pixel Differences
                diff_img = cv2.absdiff(orig_img, test_img)
                diff_gray = cv2.cvtColor(diff_img, cv2.COLOR_RGB2GRAY)
                fig4, ax4 = plt.subplots()
                ax4.hist(diff_gray.ravel(), bins=50, color='gray')
                ax4.set_title("Histogram of Pixel Differences")
                ax4.set_xlabel("Pixel Difference")
                ax4.set_ylabel("Pixel Count")
                st.pyplot(fig4)

                st.info("""
- **Histogram**: Differences suggest intensity manipulation or cut-paste.
- **Noise Map Histogram**: Unusual peaks/variance can signal copy-move or splicing.
- **Blockwise Tamper**: High bars indicate local tamper activity.
- **Pixel Difference Histogram**: Heavy right-side tail suggests significant local changes.
""")

with tab3:
    st.header("🔬 Advanced Digital Forensic Analysis")
    
    # Forensic Analysis Mode Selection
    forensic_mode = st.radio(
        "Select Forensic Analysis Mode",
        ["Basic Analysis", "Advanced Comprehensive Analysis", "Tampering Detection", "Metadata Analysis", "Device/GPS Investigation"],
        help="Choose the level of forensic analysis to perform"
    )
    
    # Image selection for analysis
    col1, col2 = st.columns(2)
    with col1:
        image_choice = st.selectbox(
            "Choose image source",
            ["Upload New Image", "Use Original", "Use Watermarked", "Use Tampered/Recovered"],
            help="Select the image source for forensic analysis"
        )
    
    with col2:
        if image_choice == "Upload New Image":
            uploaded_forensic = st.file_uploader(
                "Upload image for forensic analysis",
                type=["png", "jpg", "jpeg", "tif", "bmp"],
                key="forensic_upload"
            )
            forensic_image = None
            if uploaded_forensic:
                file_bytes = np.asarray(bytearray(uploaded_forensic.read()), np.uint8)
                forensic_image = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
                forensic_image = cv2.cvtColor(forensic_image, cv2.COLOR_BGR2RGB)
        else:
            # Use existing images from session
            if image_choice == "Use Original" and "img" in st.session_state:
                forensic_image = st.session_state.get("original_image", None)
            elif image_choice == "Use Watermarked" and "wm_img" in st.session_state:
                forensic_image = st.session_state.get("watermarked_image", None)
            elif image_choice == "Use Tampered/Recovered" and "test_img" in st.session_state:
                forensic_image = st.session_state.get("tampered_image", None)
            else:
                forensic_image = None
                st.info("No image available for this option. Please upload an image or process images in other tabs first.")
    
    if forensic_image is not None:
        # Display the image being analyzed
        st.subheader("Image Under Analysis")
        st.image(forensic_image, caption="Forensic Analysis Image", use_container_width=True)
        
        # Perform selected forensic analysis
        if st.button("🔍 Run Forensic Analysis", type="primary"):
            with st.spinner("Performing comprehensive forensic analysis..."):
                
                if forensic_mode == "Basic Analysis":
                    # Basic histogram and noise analysis
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.subheader("📊 Histogram Analysis")
                        hist = image_histogram(forensic_image)
                        fig, ax = plt.subplots(figsize=(8, 4))
                        ax.plot(hist, color="black", linewidth=2)
                        ax.set_xlim([0, 255])
                        ax.set_xlabel("Pixel Intensity", fontsize=12)
                        ax.set_ylabel("Normalized Frequency", fontsize=12)
                        ax.set_title("Grayscale Histogram", fontsize=14, fontweight='bold')
                        ax.grid(True, alpha=0.3)
                        st.pyplot(fig)
                        plt.close(fig)
                    
                    with col2:
                        st.subheader("🔊 Noise Pattern Analysis")
                        noise = noise_map(forensic_image)
                        noise_norm = (noise - noise.min()) / (np.ptp(noise) + 1e-9)
                        fig, ax = plt.subplots(figsize=(8, 4))
                        ax.hist(noise_norm.ravel(), bins=50, color='orange', alpha=0.7, edgecolor='black')
                        ax.set_xlabel("Normalized Noise Value", fontsize=12)
                        ax.set_ylabel("Pixel Count", fontsize=12)
                        ax.set_title("Noise Distribution", fontsize=14, fontweight='bold')
                        ax.grid(True, alpha=0.3)
                        st.pyplot(fig)
                        plt.close(fig)
                    
                    # Copy-move detection
                    st.subheader("🔄 Copy-Move Forgery Detection")
                    cm_mask = copy_move_detection(forensic_image, block=8, stride=4, threshold=0.97)
                    col1, col2 = st.columns([1, 2])
                    with col1:
                        st.image(cm_mask, caption="Copy-Move Suspect Regions", use_container_width=True)
                    with col2:
                        st.info("""
                        **Copy-Move Detection Analysis:**
                        - Bright regions indicate potential copy-move forgery
                        - Blocks with high similarity scores are highlighted
                        - This is an experimental feature requiring manual verification
                        - False positives can occur in textured regions
                        """)
                
                elif forensic_mode == "Advanced Comprehensive Analysis":
                    # Full advanced forensic analysis
                    results = advanced_forensic_analysis(forensic_image)
                    
                    if "error" in results:
                        st.error(f"Analysis failed: {results['error']}")
                    else:
                        # Create forensic dashboard
                        dashboard = create_forensic_dashboard(results)
                        
                        # Display forensic score and assessment
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric(
                                "Forensic Score",
                                f"{results.get('forensic_score', 0):.1f}/10",
                                delta=None,
                                help="Overall forensic analysis score (higher = more suspicious)"
                            )
                        with col2:
                            tampering_level = results.get('tampering_likelihood', 'Unknown')
                            if 'High' in tampering_level:
                                st.error(f"🚨 {tampering_level}")
                            elif 'Moderate' in tampering_level:
                                st.warning(f"⚡ {tampering_level}")
                            elif 'Low' in tampering_level:
                                st.info(f"ℹ️ {tampering_level}")
                            else:
                                st.success(f"✅ {tampering_level}")
                        with col3:
                            st.metric(
                                "Analysis Confidence",
                                f"{min(100, results.get('forensic_score', 0) * 10):.0f}%",
                                help="Confidence level based on forensic indicators"
                            )
                        
                        # Display key indicators
                        if dashboard.get('key_indicators'):
                            st.subheader("🎯 Key Forensic Indicators")
                            for indicator in dashboard['key_indicators']:
                                st.write(f"• {indicator}")
                        
                        # Detailed analysis sections
                        tabs = st.tabs([
                            "🔍 Noise Pattern Analysis",
                            "📊 Error Level Analysis",
                            "📈 Histogram Anomalies",
                            "🔐 Integrity Verification"
                        ])
                        
                        with tabs[0]:
                            if "noise_analysis" in results and "error" not in results["noise_analysis"]:
                                noise_data = results["noise_analysis"]
                                
                                col1, col2 = st.columns(2)
                                with col1:
                                    st.subheader("Gaussian Noise Characteristics")
                                    if "gaussian_noise" in noise_data:
                                        gn = noise_data["gaussian_noise"]
                                        st.write(f"Signal-to-Noise Ratio: {gn.get('snr', 0):.2f}")
                                        st.write(f"Standard Deviation: {gn.get('std', 0):.2f}")
                                        st.write(f"Gaussian Likelihood: {gn.get('gaussian_likelihood', 0):.3f}")
                                        
                                        # SNR gauge
                                        snr_value = gn.get('snr', 0)
                                        if snr_value < 5:
                                            st.error("Poor SNR - High noise levels detected")
                                        elif snr_value < 15:
                                            st.warning("Moderate SNR - Some noise present")
                                        else:
                                            st.success("Good SNR - Low noise levels")
                                
                                with col2:
                                    st.subheader("Compression & Filter Traces")
                                    if "compression_artifacts" in noise_data:
                                        ca = noise_data["compression_artifacts"]
                                        st.write(f"JPEG Artifacts: {'Detected' if ca.get('likely_jpeg', False) else 'Not detected'}")
                                        st.write(f"Blocking Severity: {ca.get('blocking_severity', 0):.2f}")
                                    
                                    if "median_filter_traces" in noise_data:
                                        mf = noise_data["median_filter_traces"]
                                        st.write(f"Median Filter Traces: {'Detected' if mf.get('likely_median_filtered', False) else 'Not detected'}")
                                        st.write(f"Histogram Smoothness: {mf.get('histogram_smoothness', 0):.2f}")
                        
                        with tabs[1]:
                            if "error_level_analysis" in results and "error" not in results["error_level_analysis"]:
                                ela_data = results["error_level_analysis"]
                                
                                col1, col2 = st.columns([2, 1])
                                with col1:
                                    st.subheader("Error Level Analysis Map")
                                    if "error_level_map" in ela_data:
                                        fig, ax = plt.subplots(figsize=(10, 8))
                                        im = ax.imshow(ela_data["error_level_map"], cmap='hot', interpolation='nearest')
                                        ax.set_title("Error Level Analysis - Suspicious Regions", fontsize=14, fontweight='bold')
                                        plt.colorbar(im, ax=ax, label='Error Level')
                                        ax.axis('off')
                                        st.pyplot(fig)
                                        plt.close(fig)
                                
                                with col2:
                                    st.subheader("ELA Statistics")
                                    st.write(f"Mean Error: {ela_data.get('mean_error', 0):.3f}")
                                    st.write(f"Error Std Dev: {ela_data.get('std_error', 0):.3f}")
                                    st.write(f"ELA Score: {ela_data.get('ela_score', 0):.3f}")
                                    st.write(f"Suspicious Regions: {ela_data.get('suspicious_regions', 0)*100:.2f}%")
                                    
                                    if ela_data.get('likely_tampered', False):
                                        st.error("⚠️ ELA indicates potential tampering")
                                    else:
                                        st.success("✅ ELA shows no significant tampering")
                        
                        with tabs[2]:
                            if "histogram_analysis" in results and "error" not in results["histogram_analysis"]:
                                hist_data = results["histogram_analysis"]
                                
                                st.subheader("Histogram Anomaly Analysis")
                                if "channel_analysis" in hist_data:
                                    channels = hist_data["channel_analysis"]
                                    
                                    # Channel comparison
                                    fig, axes = plt.subplots(2, 2, figsize=(15, 10))
                                    axes = axes.flatten()
                                    
                                    for i, (channel, analysis) in enumerate(channels.items()):
                                        if "error" not in analysis:
                                            ax = axes[i]
                                            # Create sample histogram for visualization
                                            channel_hist = cv2.calcHist([forensic_image], [["R", "G", "B"].index(channel)], None, [256], [0, 256])
                                            ax.plot(channel_hist, color=channel.lower(), linewidth=2, alpha=0.8)
                                            ax.set_title(f"Channel {channel} - Anomaly Score: {analysis.get('anomaly_score', 0):.2f}", 
                                                        fontsize=12, fontweight='bold')
                                            ax.set_xlabel("Pixel Intensity")
                                            ax.set_ylabel("Frequency")
                                            ax.grid(True, alpha=0.3)
                                            
                                            if analysis.get('likely_manipulated', False):
                                                ax.text(0.5, 0.9, "MANIPULATION DETECTED", transform=ax.transAxes, 
                                                       ha='center', va='center', bbox=dict(boxstyle='round', facecolor='red', alpha=0.7))
                                    
                                    # Remove empty subplot
                                    if len(channels) < 4:
                                        fig.delaxes(axes[3])
                                    
                                    plt.tight_layout()
                                    st.pyplot(fig)
                                    plt.close(fig)
                        
                        with tabs[3]:
                            if "image_hash" in results and "error" not in results["image_hash"]:
                                hash_data = results["image_hash"]
                                
                                st.subheader("🔐 Image Integrity Verification")
                                col1, col2 = st.columns(2)
                                
                                with col1:
                                    st.write("**Cryptographic Hashes:**")
                                    st.code(f"MD5: {hash_data.get('md5', 'N/A')}", language='text')
                                    st.code(f"SHA1: {hash_data.get('sha1', 'N/A')}", language='text')
                                    st.code(f"SHA256: {hash_data.get('sha256', 'N/A')}", language='text')
                                
                                with col2:
                                    st.write("**Perceptual Hash:**")
                                    perceptual_hash = hash_data.get('perceptual_hash', 'N/A')
                                    st.code(f"{perceptual_hash[:50]}...", language='text')
                                    st.info("Perceptual hash can be used to detect similar images even after modifications")
                        
                        # Generate and download forensic report
                        st.subheader("📋 Forensic Report Generation")
                        if st.button("Generate Detailed Forensic Report"):
                            report = forensic_analyzer.generate_forensic_report(results)
                            st.download_button(
                                label="📥 Download Forensic Report",
                                data=report,
                                file_name=f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                                mime="text/plain"
                            )
                            
                            # Save report to file
                            report_filename = f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                            report_path = os.path.join(FORENSIC_REPORTS_DIR, report_filename)
                            with open(report_path, 'w') as f:
                                f.write(report)
                            
                            st.success(f"Forensic report saved to: {report_path}")
                
                elif forensic_mode == "Tampering Detection":
                    # Focused tampering detection
                    st.subheader("🚨 Tampering Detection Analysis")
                    
                    # Quick ELA analysis
                    with st.spinner("Performing Error Level Analysis..."):
                        ela_results = forensic_analyzer.perform_error_level_analysis(forensic_image)
                        
                        if "error" not in ela_results:
                            col1, col2 = st.columns([2, 1])
                            
                            with col1:
                                st.write("**Error Level Analysis Map:**")
                                fig, ax = plt.subplots(figsize=(10, 8))
                                im = ax.imshow(ela_results["error_level_map"], cmap='hot', interpolation='nearest')
                                ax.set_title("ELA - Tampering Detection", fontsize=14, fontweight='bold')
                                plt.colorbar(im, ax=ax, label='Error Level')
                                ax.axis('off')
                                st.pyplot(fig)
                                plt.close(fig)
                            
                            with col2:
                                st.write("**Tampering Indicators:**")
                                st.metric("ELA Score", f"{ela_results.get('ela_score', 0):.3f}")
                                st.metric("Suspicious Regions", f"{ela_results.get('suspicious_regions', 0)*100:.1f}%")
                                
                                if ela_results.get('likely_tampered', False):
                                    st.error("🚨 HIGH TAMPERING RISK")
                                    st.write("The image shows significant signs of manipulation.")
                                else:
                                    st.success("✅ LOW TAMPERING RISK")
                                    st.write("No significant tampering indicators detected.")
                
                elif forensic_mode == "Metadata Analysis":
                    # EXIF and metadata analysis
                    st.subheader("📄 Image Metadata Analysis")
                    
                    # Save temporary file for EXIF analysis
                    temp_path = f"temp_forensic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
                    cv2.imwrite(temp_path, cv2.cvtColor(forensic_image, cv2.COLOR_RGB2BGR))
                    
                    try:
                        exif_data = forensic_analyzer.extract_exif_metadata(temp_path)
                        
                        if "error" not in exif_data:
                            st.write("**EXIF Metadata Found:**")
                            
                            # Organize metadata by categories
                            camera_info = {}
                            image_info = {}
                            gps_info = {}
                            other_info = {}
                            
                            for key, value in exif_data.items():
                                key_lower = key.lower()
                                if any(term in key_lower for term in ['camera', 'lens', 'make', 'model', 'serial']):
                                    camera_info[key] = value
                                elif any(term in key_lower for term in ['width', 'height', 'resolution', 'bit', 'color']):
                                    image_info[key] = value
                                elif any(term in key_lower for term in ['gps', 'latitude', 'longitude']):
                                    gps_info[key] = value
                                else:
                                    other_info[key] = value
                            
                            # Display organized metadata
                            if camera_info:
                                st.write("**Camera Information:**")
                                for key, value in camera_info.items():
                                    st.write(f"• {key}: {value}")
                            
                            if image_info:
                                st.write("**Image Properties:**")
                                for key, value in image_info.items():
                                    st.write(f"• {key}: {value}")
                            
                            if gps_info:
                                st.write("**GPS Information:**")
                                for key, value in gps_info.items():
                                    st.write(f"• {key}: {value}")
                            
                            if other_info:
                                st.write("**Additional Metadata:**")
                                for key, value in list(other_info.items())[:10]:  # Limit display
                                    st.write(f"• {key}: {value}")
                                
                                if len(other_info) > 10:
                                    st.write(f"... and {len(other_info) - 10} more metadata fields")
                        else:
                            st.info("No EXIF metadata found in the image.")
                    
                    finally:
                        # Clean up temporary file
                        if os.path.exists(temp_path):
                            os.remove(temp_path)
                
                elif forensic_mode == "Device/GPS Investigation":
                    # Law enforcement-grade device and GPS investigation
                    st.subheader("🚔 Law Enforcement Device/GPS Investigation")
                    
                    # Save temporary file for enhanced analysis
                    temp_path = f"temp_forensic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
                    cv2.imwrite(temp_path, cv2.cvtColor(forensic_image, cv2.COLOR_RGB2BGR))
                    
                    try:
                        with st.spinner("Performing comprehensive device and GPS forensic analysis..."):
                            # Enhanced metadata extraction
                            enhanced_results = enhanced_device_forensic_analysis(temp_path)
                            
                            if "error" not in enhanced_results:
                                # Create evidence chain
                                evidence_chain = create_evidence_chain(temp_path, enhanced_results)
                                
                                # Display investigation dashboard
                                st.subheader("🔍 Investigation Dashboard")
                                
                                col1, col2, col3 = st.columns(3)
                                
                                with col1:
                                    st.metric("Case ID", evidence_chain.get('case_id', 'Unknown'))
                                    st.metric("Evidence ID", evidence_chain.get('evidence_id', 'Unknown'))
                                
                                with col2:
                                    tampering_score = enhanced_results.get('tampering_analysis', {}).get('metadata_tampering_score', 0)
                                    st.metric("Tampering Score", f"{tampering_score}/10")
                                    
                                    confidence = 'High' if tampering_score >= 6 else 'Medium' if tampering_score >= 3 else 'Low'
                                    st.metric("Confidence Level", confidence)
                                
                                with col3:
                                    device_info = enhanced_results.get('device_info', {})
                                    device_type = enhanced_results.get('device_fingerprint', {}).get('device_type', 'Unknown')
                                    st.metric("Device Type", device_type)
                                    
                                    has_gps = device_info.get('has_gps', False)
                                    st.metric("GPS Data", "Available" if has_gps else "Not Found")
                                
                                # Device Information Section
                                st.subheader("📱 Device Information")
                                device_tabs = st.tabs(["Device Details", "Camera Settings", "GPS Location", "Tampering Analysis"])
                                
                                with device_tabs[0]:
                                    if device_info:
                                        col1, col2 = st.columns(2)
                                        with col1:
                                            st.write("**Device Manufacturer:**")
                                            st.code(f"Manufacturer: {device_info.get('manufacturer', 'Unknown')}")
                                            st.code(f"Model: {device_info.get('model', 'Unknown')}")
                                            st.code(f"Serial Number: {device_info.get('serial_number', 'Unknown')}")
                                            st.code(f"Software: {device_info.get('software', 'Unknown')}")
                                        
                                        with col2:
                                            st.write("**Lens Information:**")
                                            st.code(f"Lens Manufacturer: {device_info.get('lens_manufacturer', 'Unknown')}")
                                            st.code(f"Lens Model: {device_info.get('lens_model', 'Unknown')}")
                                            st.code(f"Lens Serial: {device_info.get('lens_serial', 'Unknown')}")
                                            st.code(f"Has GPS: {'Yes' if device_info.get('has_gps') else 'No'}")
                                
                                with device_tabs[1]:
                                    camera_settings = enhanced_results.get('camera_settings', {})
                                    if camera_settings:
                                        col1, col2 = st.columns(2)
                                        with col1:
                                            st.write("**Exposure Settings:**")
                                            st.code(f"Exposure Time: {camera_settings.get('exposure_time', 'Unknown')}")
                                            st.code(f"F-Number: {camera_settings.get('f_number', 'Unknown')}")
                                            st.code(f"ISO Speed: {camera_settings.get('iso_speed', 'Unknown')}")
                                            st.code(f"Focal Length: {camera_settings.get('focal_length', 'Unknown')}")
                                        
                                        with col2:
                                            st.write("**Camera Mode:**")
                                            st.code(f"Flash: {camera_settings.get('flash', {}).get('status', 'Unknown') if isinstance(camera_settings.get('flash'), dict) else camera_settings.get('flash', 'Unknown')}")
                                            st.code(f"White Balance: {camera_settings.get('white_balance', 'Unknown')}")
                                            st.code(f"Metering Mode: {camera_settings.get('metering_mode', 'Unknown')}")
                                            st.code(f"Color Space: {camera_settings.get('color_space', 'Unknown')}")
                                
                                with device_tabs[2]:
                                    gps_info = enhanced_results.get('gps_info', {})
                                    if gps_info and gps_info.get('coordinates'):
                                        st.write("**GPS Coordinates:**")
                                        st.code(f"Latitude: {gps_info.get('latitude', 'Unknown')}")
                                        st.code(f"Longitude: {gps_info.get('longitude', 'Unknown')}")
                                        st.code(f"Altitude: {gps_info.get('altitude', 'Unknown')}")
                                        
                                        location_name = gps_info.get('location_name', {})
                                        if location_name and 'error' not in location_name:
                                            st.write("**Location Details:**")
                                            st.code(f"Address: {location_name.get('full_address', 'Unknown')}")
                                            st.code(f"Country: {location_name.get('country', 'Unknown')}")
                                            st.code(f"City: {location_name.get('city', 'Unknown')}")
                                            st.code(f"Road: {location_name.get('road', 'Unknown')}")
                                        
                                        accuracy = gps_info.get('location_accuracy', {})
                                        if accuracy:
                                            st.write("**Location Accuracy:**")
                                            st.code(f"Accuracy Level: {accuracy.get('estimated_accuracy', 'Unknown')}")
                                            st.code(f"Satellites Used: {accuracy.get('satellites_used', 'Unknown')}")
                                    else:
                                        st.warning("No GPS data found in image metadata")
                                
                                with device_tabs[3]:
                                    tampering_analysis = enhanced_results.get('tampering_analysis', {})
                                    if tampering_analysis:
                                        st.write("**Tampering Indicators:**")
                                        st.code(f"Metadata Tampering Score: {tampering_analysis.get('metadata_tampering_score', 0)}/10")
                                        st.code(f"Editing Software Detected: {'Yes' if tampering_analysis.get('editing_detected') else 'No'}")
                                        st.code(f"Software: {tampering_analysis.get('editing_software', 'Unknown')}")
                                        st.code(f"Timestamp Suspicious: {'Yes' if tampering_analysis.get('timestamp_suspicious') else 'No'}")
                                        st.code(f"Custom Rendering: {'Yes' if tampering_analysis.get('custom_rendering') else 'No'}")
                                        
                                        st.write(f"**Assessment:** {tampering_analysis.get('tampering_likelihood', 'Unknown')}")
                                    else:
                                        st.info("No tampering indicators detected")
                                
                                # Generate comprehensive investigation report
                                st.subheader("📋 Investigation Report")
                                if st.button("Generate Law Enforcement Investigation Report", type="primary"):
                                    investigation_report = generate_investigation_report(evidence_chain, enhanced_results)
                                    
                                    st.download_button(
                                        label="📥 Download Investigation Report",
                                        data=investigation_report,
                                        file_name=f"investigation_report_{evidence_chain.get('case_id', 'unknown')}.txt",
                                        mime="text/plain"
                                    )
                                    
                                    # Save report to file
                                    report_filename = f"investigation_report_{evidence_chain.get('case_id', 'unknown')}.txt"
                                    report_path = os.path.join(FORENSIC_REPORTS_DIR, report_filename)
                                    with open(report_path, 'w') as f:
                                        f.write(investigation_report)
                                    
                                    st.success(f"Investigation report saved to: {report_path}")
                                    
                                    # Display report preview
                                    with st.expander("📖 Report Preview"):
                                        st.text(investigation_report[:2000] + "..." if len(investigation_report) > 2000 else investigation_report)
                            
                            else:
                                st.error(f"Enhanced forensic analysis failed: {enhanced_results.get('error', 'Unknown error')}")
                    
                    finally:
                        # Clean up temporary file
                        if os.path.exists(temp_path):
                            os.remove(temp_path)
        
        else:
            st.info("Upload an image and click 'Run Forensic Analysis' to begin.")
    
    else:
        st.info("Please upload an image or process images in other tabs to enable forensic analysis.")
    
    # Forensic analysis history
    if st.checkbox("Show Forensic Analysis History"):
        st.subheader("📚 Forensic Analysis History")
        if "forensic_history" not in st.session_state:
            st.session_state.forensic_history = []
        
        if st.session_state.forensic_history:
            for i, analysis in enumerate(st.session_state.forensic_history[-5:]):  # Show last 5
                st.write(f"**Analysis {i+1}** - {analysis.get('timestamp', 'Unknown')}")
                st.write(f"Score: {analysis.get('forensic_score', 0):.1f}/10")
                st.write(f"Result: {analysis.get('tampering_likelihood', 'Unknown')}")
                st.write("---")
        else:
            st.write("No forensic analysis history available.")

st.markdown("---")
st.caption("©2024 Secure Color Image Watermark & Forensic Recovery System")
