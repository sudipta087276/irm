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

# ---- Directories ----
WM_DIR = "data/Watermarked"
RCV_DIR = "data/Recovered"
os.makedirs(WM_DIR, exist_ok=True)
os.makedirs(RCV_DIR, exist_ok=True)

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
    h, w, _ = orig.shape
    mask = np.zeros((h, w), dtype=np.uint8)
    heatmap = np.zeros((h//block, w//block))
    report = []
    for y in range(0, h, block):
        for x in range(0, w, block):
            bo = orig[y:y+block, x:x+block, :]
            bt = test[y:y+block, x:x+block, :]
            diff = np.abs(bo.astype(np.int16) - bt.astype(np.int16))
            v = np.max(diff)
            tampered = v > thresh
            if tampered:
                mask[y:y+block, x:x+block] = 255
            heatmap[y//block, x//block] = v
            report.append({
                "block_y": y//block, "block_x": x//block,
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
        scores["PSNR"] = float(psnr(orig, test, data_range=255))
        scores["SSIM"] = float(ssim(orig, test, channel_axis=2, data_range=255))
        norm_corr = float(np.corrcoef(orig.flatten(), test.flatten())[0, 1])
        scores["NC"] = norm_corr
    except Exception as e:
        scores["error"] = str(e)
    return scores

# Passive attack detection functions
def image_histogram(img):
    gray = cv2.cvtColor(img, cv2.COLOR_RGB2GRAY)
    hist = cv2.calcHist([gray], [0], None, [256], [0, 256])
    hist = hist.flatten()
    return hist / hist.sum()

def noise_map(img):
    gray = cv2.cvtColor(img, cv2.COLOR_RGB2GRAY)
    noise = gaussian_laplace(gray.astype(float), sigma=1)
    return np.abs(noise)

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
        st.image(img, caption="Original", use_container_width=True)
        code = custom_code if custom_code else random_code()
        logo = None
        if logo_up:
            logo_bytes = np.asarray(bytearray(logo_up.read()), np.uint8)
            logo = cv2.imdecode(logo_bytes, cv2.IMREAD_COLOR)
            logo = cv2.cvtColor(logo, cv2.COLOR_BGR2RGB)
        wm_img = embed_watermark_color(img, code, logo, strength)
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
    st.header("Passive Attack & Forensic Analysis")
    image_choice = st.radio("Choose an image to analyze", ("None", "Original", "Watermarked", "Tampered"))
    # You can upload or reuse last images for passive forensics.
    img = None
    if image_choice != "None":
        if image_choice == "Original" and "img" in locals():
            img = locals().get("img", None)
        elif image_choice == "Watermarked" and "wm_img" in locals():
            img = locals().get("wm_img", None)
        elif image_choice == "Tampered" and "test_img" in locals():
            img = locals().get("test_img", None)
    user_img = st.file_uploader("Or upload an image for passive analysis", type=["png", "jpg", "jpeg", "tif"], key="forensic")
    if user_img:
        file_bytes = np.asarray(bytearray(user_img.read()), np.uint8)
        img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
        img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)

    if img is not None:
        # Histogram
        st.subheader("Histogram (grayscale)")
        hist = image_histogram(img)
        fig, ax = plt.subplots()
        ax.plot(hist, color="black")
        ax.set_xlim([0, 255])
        st.pyplot(fig)
        # Noise map
        st.subheader("Noise Map (Laplacian)")
        noise = noise_map(img)
        # Fixed for NumPy 2.x: use np.ptp(noise)
        noise_norm = (noise - noise.min()) / (np.ptp(noise) + 1e-9)
        st.image(noise_norm, caption="Noise Map", use_container_width=True)
        # Copy-move detection
        st.subheader("Copy-Move Forgery Block Detection (experimental)")
        cm_mask = copy_move_detection(img, block=8, stride=4, threshold=0.97)
        st.image(cm_mask, caption="Copy-Move Suspect Regions", use_container_width=True)
        st.info("Bright blocks may indicate copy-move or local block duplication. True forensics requires manual review and further methods.")

st.markdown("---")
st.caption("©2024 Secure Color Image Watermark & Forensic Recovery System")
