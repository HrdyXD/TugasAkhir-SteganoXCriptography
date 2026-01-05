import streamlit as st
import streamlit.components.v1 as components
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from PIL import Image
import io, random
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# ===== KONSTANTA =====
HEADER_BYTES = 11
HEADER_BITS = HEADER_BYTES * 8
MAX_SHOW_PIXELS = 300


# ===== UI PREMIUM: SCROLLABLE TABLE =====
def scrollable_table(df: pd.DataFrame, height: int = 260):

    if df is None or df.empty:
        st.info("📭 Tidak ada data ditampilkan")
        return

    table_html = df.to_html(
        index=False,
        classes="nice-table",
        escape=False
    )

    html = f"""
    <html>
    <head>
    <style>

        body {{
            background-color: #0e1117 !important;
            color: #ffffff !important;
        }}

        .table-wrapper {{
            max-height: {height}px;
            overflow-y: auto;
            overflow-x: auto;
            border-radius: 12px;
            border: 1px solid rgba(255,255,255,0.15);
            background-color: #0e1117;
        }}

        table.nice-table {{
            border-collapse: collapse;
            width: 100%;
            font-family: 'Segoe UI', sans-serif;
            font-size: 13px;
            background-color: #0e1117 !important;
            color: #ffffff !important;
        }}

        table.nice-table thead th {{
            position: sticky;
            top: 0;
            background-color: #1a1d23 !important;
            padding: 10px 8px;
            font-weight: 600;
            text-align: left;
            color: #ffffff !important;
            border-bottom: 1px solid rgba(255,255,255,0.25);
        }}

        table.nice-table td {{
            padding: 8px 10px;
            border-bottom: 1px solid rgba(255,255,255,0.07);
            color: #ffffff !important;
            background-color: #0e1117 !important;
        }}

        table.nice-table tr:nth-child(even) td {{
            background-color: #11151c !important;
        }}

        table.nice-table tr:hover td {{
            background-color: #1b1f26 !important;
        }}

    </style>
    </head>

    <body>
        <div class="table-wrapper">
            {table_html}
        </div>
    </body>
    </html>
    """

    components.html(html, height=height + 50, scrolling=True)


# ===== RSA HELPERS =====
def generate_rsa_keypair(bits=2048):
    key = RSA.generate(bits)
    return key.export_key(), key.publickey().export_key()


def rsa_encrypt(pub, data_bytes):
    cipher = PKCS1_OAEP.new(pub)
    return cipher.encrypt(data_bytes)


def rsa_decrypt(priv, ciphertext):
    cipher = PKCS1_OAEP.new(priv)
    return cipher.decrypt(ciphertext)


# ===== BIT OPERATIONS =====
def _to_bitstring(b):
    return ''.join(f"{x:08b}" for x in b)


def _from_bitstring(s):
    return bytes(int(s[i:i+8], 2) for i in range(0, len(s), 8))


def int_to_bytes_be(n, length):
    return n.to_bytes(length, 'big')


def build_header_bits(random_flag, seed, msg_bits):
    b = bytearray()
    b.extend(b"ST")  
    b.append(1 if random_flag else 0)
    b.extend(int_to_bytes_be(seed & 0xffffffff, 4))
    b.extend(int_to_bytes_be(msg_bits & 0xffffffff, 4))
    return ''.join(format(x, '08b') for x in b)


def parse_header_from_bits(bitstr):
    if len(bitstr) < HEADER_BITS:
        return None
    bs = bytearray(int(bitstr[i:i+8],2) for i in range(0, HEADER_BITS, 8))
    if bs[:2] != b"ST":
        return None
    return {
        "random": bool(bs[2] & 1),
        "seed": int.from_bytes(bs[3:7], "big"),
        "msg_len_bits": int.from_bytes(bs[7:11], "big")
    }


# ===== IMAGE OPS =====
def coords_from_index(idx, width):
    return idx % width, idx // width


def embed_ciphertext_into_channel(img, ciphertext, channel, use_random, seed=None):

    if img.mode != "RGB":
        img = img.convert("RGB")

    w, h = img.size
    total = w * h
    ch = {"R":0, "G":1, "B":2}[channel]

    msg_bits = _to_bitstring(ciphertext)
    nbits = len(msg_bits)

    # seed
    if use_random:
        if seed is None:
            seed = random.getrandbits(32)
    else:
        seed = 0

    header_bits = build_header_bits(use_random, seed, nbits)

    if nbits > total - HEADER_BITS:
        raise ValueError("Pesan terlalu besar untuk disisipkan.")

    px = list(img.getdata())
    mod = list(px)

    # tulis header
    for i, b in enumerate(header_bits):
        bit = int(b)
        p = list(mod[i])
        p[ch] = (p[ch] & ~1) | bit
        mod[i] = tuple(p)

    # posisi payload
    avail = list(range(HEADER_BITS, total))

    if use_random:
        rng = random.Random(seed)
        pos = rng.sample(avail, nbits)
    else:
        pos = avail[:nbits]

    # embed payload
    changes = []
    for i, position in enumerate(pos):
        bit = int(msg_bits[i])
        p = list(mod[position])
        old = p[ch]
        new = (old & ~1) | bit
        p[ch] = new
        mod[position] = tuple(p)
        changes.append({
            "bit_index": i,
            "pos": position,
            "coord": coords_from_index(position, w),
            "inserted_bit": bit,
            "old_pixel": px[position],
            "new_pixel": mod[position],
            "old_lsb": old & 1,
            "new_lsb": new & 1
        })

    out = Image.new("RGB", (w, h))
    out.putdata(mod)

    buf = io.BytesIO()
    out.save(buf, "PNG")
    buf.seek(0)

    return buf, {
        "file_name": None,
        "channel": channel,
        "use_random": use_random,
        "seed": seed,
        "nbits": nbits,
        "ciphertext_bytes_len": len(ciphertext),
        "changes": changes
    }


def extract_bits_from_channel(img, ch):
    px = list(img.getdata())

    header_bits = ''.join(str(px[i][ch] & 1) for i in range(HEADER_BITS))
    header = parse_header_from_bits(header_bits)
    if not header:
        return None, None, None

    nbits = header["msg_len_bits"]
    total = len(px)

    if nbits > total - HEADER_BITS:
        return None, None, None

    if header["random"]:
        rng = random.Random(header["seed"])
        avail = list(range(HEADER_BITS, total))
        pos = rng.sample(avail, nbits)
    else:
        pos = list(range(HEADER_BITS, HEADER_BITS + nbits))

    bits = ''.join(str(px[p][ch] & 1) for p in pos)

    return header, bits, pos


# ===== MSE & PSNR CALCULATION =====
def calculate_mse(img1, img2):
    """Calculate Mean Squared Error between two images"""
    arr1 = np.array(img1, dtype=np.float64)
    arr2 = np.array(img2, dtype=np.float64)
    
    mse = np.mean((arr1 - arr2) ** 2)
    
    # Per channel MSE
    mse_r = np.mean((arr1[:,:,0] - arr2[:,:,0]) ** 2)
    mse_g = np.mean((arr1[:,:,1] - arr2[:,:,1]) ** 2)
    mse_b = np.mean((arr1[:,:,2] - arr2[:,:,2]) ** 2)
    
    return {
        "overall": mse,
        "R": mse_r,
        "G": mse_g,
        "B": mse_b
    }


def calculate_psnr(mse_value, max_pixel=255.0):
    """Calculate PSNR from MSE"""
    if mse_value == 0:
        return float('inf')
    return 10 * np.log10((max_pixel ** 2) / mse_value)


def analyze_image_quality(cover_img, stego_img):
    """Comprehensive image quality analysis"""
    
    # Convert to RGB if needed
    if cover_img.mode != "RGB":
        cover_img = cover_img.convert("RGB")
    if stego_img.mode != "RGB":
        stego_img = stego_img.convert("RGB")
    
    # Check dimensions
    if cover_img.size != stego_img.size:
        raise ValueError("Gambar cover dan stego harus memiliki dimensi yang sama!")
    
    # Calculate MSE
    mse_results = calculate_mse(cover_img, stego_img)
    
    # Calculate PSNR
    psnr_results = {
        "overall": calculate_psnr(mse_results["overall"]),
        "R": calculate_psnr(mse_results["R"]),
        "G": calculate_psnr(mse_results["G"]),
        "B": calculate_psnr(mse_results["B"])
    }
    
    return {
        "mse": mse_results,
        "psnr": psnr_results,
        "dimensions": cover_img.size,
        "total_pixels": cover_img.size[0] * cover_img.size[1]
    }


# ===== STREAMLIT APP =====
st.set_page_config(page_title="RSA + LSB Stego", layout="wide")
st.title("🔐 RSA + LSB Steganografi (Premium UI)")

menu = st.sidebar.selectbox("Menu", [
    "Generate Key", 
    "Enkripsi + Stego", 
    "Ekstrak + Dekripsi",
    "Pengujian MSE dan PSNR"
])

# ================= GENERATE KEY =================
if menu == "Generate Key":
    st.header("🔑 Generate RSA Key 2048-bit")

    if st.button("Generate Key Baru"):
        priv, pub = generate_rsa_keypair()
        st.session_state["priv"] = priv
        st.session_state["pub"] = pub
        st.success("Key berhasil dibuat 🎉")

    if "priv" in st.session_state:
        st.download_button("Download Private Key", st.session_state["priv"], "private.pem")

    if "pub" in st.session_state:
        st.download_button("Download Public Key", st.session_state["pub"], "public.pem")


# ================= ENKRIPSI =================
elif menu == "Enkripsi + Stego":

    st.header("🧩 Enkripsi Seed Phrase → RSA → LSB")

    with st.form("encrypt_form"):
        col1, col2 = st.columns([2,1])

        with col1:
            msg = st.text_area("Seed phrase / pesan:", height=120)
            pubfile = st.file_uploader("Upload Public Key (PEM)", type=["pem"])
            cover = st.file_uploader("Upload Cover Image (PNG)", type=["png"])

        with col2:
            channel = st.radio("Pilih channel LSB:", ["R","G","B"])
            use_random = st.checkbox("Mode Penempatan Random?")
            seed_input = st.text_input("Seed (opsional, integer)", "")
            show_all = st.checkbox("Tampilkan SEMUA perubahan pixel?")

        ok = st.form_submit_button("Mulai Enkripsi")

    if ok:
        try:
            pub = RSA.import_key(pubfile.read())
            ciphertext = rsa_encrypt(pub, msg.encode())

            seed_val = int(seed_input) if (use_random and seed_input.strip() != "") else None

            img = Image.open(cover)
            stego_buf, summary = embed_ciphertext_into_channel(
                img, ciphertext, channel, use_random, seed_val
            )
            summary["file_name"] = cover.name

            st.success("Berhasil disisipkan ke dalam gambar! 🎉")

            st.image(stego_buf, width=350)
            st.download_button("Download Stego Image",
                               stego_buf.getvalue(),
                               f"{summary['file_name']}_stego.png")

            # ---------------- RINGKASAN ----------------
            st.subheader("📌 Ringkasan Penyisipan")
            st.write(f"Channel: **{summary['channel']}**")
            st.write(f"Random Mode: **{summary['use_random']}**")
            if summary["use_random"]:
                st.write(f"Seed: **{summary['seed']}**")
            st.write(f"Panjang ciphertext: **{summary['ciphertext_bytes_len']} bytes**")

            # Ciphertext table
            ct_table = [{"index": i, "hex": f"{b:02x}", "bin": f"{b:08b}"} 
                        for i, b in enumerate(ciphertext)]
            st.markdown("### 🔸 Ciphertext per-byte")
            scrollable_table(pd.DataFrame(ct_table), height=230)

            # Pixel changes
            rows = summary["changes"]
            showN = len(rows) if show_all else min(len(rows), HEADER_BITS)

            st.markdown("### 🔸 Perubahan Pixel (LSB)")
            pixel_table = [{
                "no": i+1,
                "index": rows[i]["pos"],
                "coord": rows[i]["coord"],
                "bit": rows[i]["inserted_bit"],
                "old": rows[i]["old_pixel"],
                "new": rows[i]["new_pixel"]
            } for i in range(showN)]

            scrollable_table(pd.DataFrame(pixel_table), height=260)

        except Exception as e:
            st.error(f"❌ Error: {e}")


# ================= DEKRIPSI =================
elif menu == "Ekstrak + Dekripsi":
    st.header("🕵️ Ekstraksi + Dekripsi RSA")

    mode = st.radio("Pilih Mode", ["Normal", "Random"])

    if mode == "Normal":
        stego = st.file_uploader("Upload Stego Image", type=["png"])
        priv = st.file_uploader("Upload Private Key", type=["pem"])

        if st.button("Ekstrak & Dekripsi"):
            try:
                img = Image.open(stego)
                priv_key = RSA.import_key(priv.read())

                found = False
                for ch_idx, cname in enumerate(["R","G","B"]):
                    header, bits, pos = extract_bits_from_channel(img, ch_idx)
                    if not header:
                        continue
                    if header["random"]:
                        st.error(f"Data ada di {cname}, tetapi memakai RANDOM. Gunakan mode RANDOM.")
                        found = True
                        break

                    ciphertext = _from_bitstring(bits)
                    dec = rsa_decrypt(priv_key, ciphertext)

                    st.success(f"Data ditemukan di channel {cname}")
                    st.code(dec.decode())

                    ct_table = [{"i": i, "hex": f"{b:02x}", "bin": f"{b:08b}"} 
                                for i,b in enumerate(ciphertext)]
                    st.markdown("### Ciphertext")
                    scrollable_table(pd.DataFrame(ct_table), height=250)

                    found = True
                    break

                if not found:
                    st.error("Tidak ada header ditemukan.")

            except Exception as e:
                st.error(f"❌ Error: {e}")

    # RANDOM MODE
    else:
        cover = st.file_uploader("Upload Cover", type=["png"])
        stego = st.file_uploader("Upload Stego", type=["png"])
        priv = st.file_uploader("Upload Private Key", type=["pem"])

        if st.button("Ekstrak Random"):
            try:
                cimg = Image.open(cover)
                simg = Image.open(stego)

                priv_key = RSA.import_key(priv.read())

                found = False

                for ch_idx, cname in enumerate(["R","G","B"]):
                    header, bits, pos = extract_bits_from_channel(simg, ch_idx)
                    if not header:
                        continue

                    ciphertext = _from_bitstring(bits)
                    dec = rsa_decrypt(priv_key, ciphertext)

                    st.success(f"Data ditemukan pada channel {cname}")
                    st.write(f"Seed: {header['seed']}")
                    st.code(dec.decode())

                    # show few pixel diffs
                    px_c = list(cimg.getdata())
                    px_s = list(simg.getdata())

                    diffs = []
                    for i, p in enumerate(pos[:MAX_SHOW_PIXELS]):
                        diffs.append({
                            "no": i+1,
                            "index": p,
                            "cover": px_c[p],
                            "stego": px_s[p]
                        })

                    scrollable_table(pd.DataFrame(diffs), height=260)

                    found = True
                    break

                if not found:
                    st.error("Tidak ada data RANDOM ditemukan")

            except Exception as e:
                st.error(f"❌ Error: {e}")


# ================= MSE & PSNR TESTING =================
elif menu == "Pengujian MSE dan PSNR":
    st.header("📊 Pengujian MSE dan PSNR")
    st.markdown("Analisis kualitas gambar stego dengan mengukur Mean Squared Error (MSE) dan Peak Signal-to-Noise Ratio (PSNR)")
    
    col1, col2 = st.columns(2)
    
    with col1:
        cover_file = st.file_uploader("📁 Upload Gambar Cover", type=["png", "jpg", "jpeg"], key="cover_mse")
    
    with col2:
        stego_file = st.file_uploader("📁 Upload Gambar Stego", type=["png", "jpg", "jpeg"], key="stego_mse")
    
    if st.button("🔬 Mulai Analisis", type="primary"):
        if cover_file is None or stego_file is None:
            st.warning("⚠️ Harap upload kedua gambar terlebih dahulu!")
        else:
            try:
                with st.spinner("Sedang menganalisis..."):
                    cover_img = Image.open(cover_file)
                    stego_img = Image.open(stego_file)
                    
                    # Perform analysis
                    results = analyze_image_quality(cover_img, stego_img)
                    
                    st.success("✅ Analisis selesai!")
                    
                    # Display images side by side
                    st.markdown("### 🖼️ Perbandingan Gambar")
                    img_col1, img_col2 = st.columns(2)
                    
                    with img_col1:
                        st.markdown("**Cover Image**")
                        st.image(cover_img, use_container_width=True)
                    
                    with img_col2:
                        st.markdown("**Stego Image**")
                        st.image(stego_img, use_container_width=True)
                    
                    # Display basic info
                    st.markdown("### 📏 Informasi Gambar")
                    info_col1, info_col2, info_col3 = st.columns(3)
                    
                    with info_col1:
                        st.metric("Lebar", f"{results['dimensions'][0]} px")
                    
                    with info_col2:
                        st.metric("Tinggi", f"{results['dimensions'][1]} px")
                    
                    with info_col3:
                        st.metric("Total Pixel", f"{results['total_pixels']:,}")
                    
                    # MSE Results
                    st.markdown("### 📉 Mean Squared Error (MSE)")
                    st.markdown("*Semakin kecil nilai MSE, semakin mirip gambar stego dengan cover*")
                    
                    mse_data = {
                        "Channel": ["Overall", "Red (R)", "Green (G)", "Blue (B)"],
                        "MSE Value": [
                            f"{results['mse']['overall']:.6f}",
                            f"{results['mse']['R']:.6f}",
                            f"{results['mse']['G']:.6f}",
                            f"{results['mse']['B']:.6f}"
                        ]
                    }
                    
                    mse_df = pd.DataFrame(mse_data)
                    st.dataframe(mse_df, use_container_width=True, hide_index=True)
                    
                    # PSNR Results
                    st.markdown("### 📈 Peak Signal-to-Noise Ratio (PSNR)")
                    st.markdown("*Semakin tinggi nilai PSNR (>30 dB), semakin baik kualitas gambar stego*")
                    
                    psnr_data = {
                        "Channel": ["Overall", "Red (R)", "Green (G)", "Blue (B)"],
                        "PSNR Value (dB)": [
                            f"{results['psnr']['overall']:.2f}",
                            f"{results['psnr']['R']:.2f}",
                            f"{results['psnr']['G']:.2f}",
                            f"{results['psnr']['B']:.2f}"
                        ],
                        "Kualitas": [
                            evaluate_psnr_quality(results['psnr']['overall']),
                            evaluate_psnr_quality(results['psnr']['R']),
                            evaluate_psnr_quality(results['psnr']['G']),
                            evaluate_psnr_quality(results['psnr']['B'])
                        ]
                    }
                    
                    psnr_df = pd.DataFrame(psnr_data)
                    st.dataframe(psnr_df, use_container_width=True, hide_index=True)
                    
                    # Visualization
                    st.markdown("### 📊 Visualisasi Grafik")
                    
                    # Create comparison charts
                    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
                    
                    # MSE Chart
                    channels = ['Overall', 'R', 'G', 'B']
                    mse_values = [
                        results['mse']['overall'],
                        results['mse']['R'],
                        results['mse']['G'],
                        results['mse']['B']
                    ]
                    
                    colors_mse = ['#FF6B6B', '#E74C3C', '#C0392B', '#A93226']
                    bars1 = ax1.bar(channels, mse_values, color=colors_mse, alpha=0.8, edgecolor='black', linewidth=1.5)
                    ax1.set_title('Mean Squared Error (MSE)', fontsize=14, fontweight='bold', pad=15)
                    ax1.set_ylabel('MSE Value', fontsize=11)
                    ax1.set_xlabel('Channel', fontsize=11)
                    ax1.grid(axis='y', alpha=0.3, linestyle='--')
                    ax1.set_facecolor('#f8f9fa')
                    
                    # Add value labels on bars
                    for bar in bars1:
                        height = bar.get_height()
                        ax1.text(bar.get_x() + bar.get_width()/2., height,
                                f'{height:.4f}',
                                ha='center', va='bottom', fontsize=9, fontweight='bold')
                    
                    # PSNR Chart
                    psnr_values = [
                        results['psnr']['overall'],
                        results['psnr']['R'],
                        results['psnr']['G'],
                        results['psnr']['B']
                    ]
                    
                    colors_psnr = ['#4ECDC4', '#45B7D1', '#3498DB', '#2980B9']
                    bars2 = ax2.bar(channels, psnr_values, color=colors_psnr, alpha=0.8, edgecolor='black', linewidth=1.5)
                    ax2.set_title('Peak Signal-to-Noise Ratio (PSNR)', fontsize=14, fontweight='bold', pad=15)
                    ax2.set_ylabel('PSNR (dB)', fontsize=11)
                    ax2.set_xlabel('Channel', fontsize=11)
                    ax2.grid(axis='y', alpha=0.3, linestyle='--')
                    ax2.axhline(y=30, color='red', linestyle='--', linewidth=2, alpha=0.7, label='Threshold (30 dB)')
                    ax2.legend(loc='lower right')
                    ax2.set_facecolor('#f8f9fa')
                    
                    # Add value labels on bars
                    for bar in bars2:
                        height = bar.get_height()
                        ax2.text(bar.get_x() + bar.get_width()/2., height,
                                f'{height:.2f}',
                                ha='center', va='bottom', fontsize=9, fontweight='bold')
                    
                    plt.tight_layout()
                    st.pyplot(fig)
                    
                    # Quality Assessment
                    st.markdown("### 🎯 Kesimpulan Kualitas")
                    
                    overall_psnr = results['psnr']['overall']
                    overall_mse = results['mse']['overall']
                    
                    if overall_psnr >= 40:
                        quality_status = "🟢 **Excellent** - Kualitas sangat baik, perubahan hampir tidak terlihat"
                        quality_color = "green"
                    elif overall_psnr >= 30:
                        quality_status = "🟡 **Good** - Kualitas baik, perubahan minimal"
                        quality_color = "blue"
                    elif overall_psnr >= 20:
                        quality_status = "🟠 **Fair** - Kualitas cukup, perubahan mulai terlihat"
                        quality_color = "orange"
                    else:
                        quality_status = "🔴 **Poor** - Kualitas rendah, perubahan terlihat jelas"
                        quality_color = "red"
                    
                    st.markdown(f"**Status Kualitas:** {quality_status}")
                    st.markdown(f"- **Overall PSNR:** {overall_psnr:.2f} dB")
                    st.markdown(f"- **Overall MSE:** {overall_mse:.6f}")
                    
                    # Additional insights
                    with st.expander("ℹ️ Informasi Tambahan tentang MSE dan PSNR"):
                        st.markdown("""
                        **Mean Squared Error (MSE):**
                        - Mengukur rata-rata kuadrat perbedaan antara nilai pixel gambar cover dan stego
                        - Nilai MSE = 0 berarti kedua gambar identik
                        - Semakin kecil nilai MSE, semakin baik kualitas steganografi
                        
                        **Peak Signal-to-Noise Ratio (PSNR):**
                        - Mengukur rasio antara nilai maksimum sinyal dengan noise
                        - Satuan: desibel (dB)
                        - Interpretasi nilai PSNR:
                          - **> 40 dB:** Excellent - Perubahan hampir tidak terdeteksi
                          - **30-40 dB:** Good - Kualitas baik untuk steganografi
                          - **20-30 dB:** Fair - Perubahan mulai terlihat
                          - **< 20 dB:** Poor - Perubahan jelas terlihat
                        
                        **Formula:**
                        - MSE = (1/n) × Σ(Cover - Stego)²
                        - PSNR = 10 × log₁₀(255² / MSE)
                        """)
                    
            except Exception as e:
                st.error(f"❌ Error saat analisis: {e}")


def evaluate_psnr_quality(psnr_value):
    """Evaluate PSNR quality"""
    if psnr_value >= 40:
        return "🟢 Excellent"
    elif psnr_value >= 30:
        return "🟡 Good"
    elif psnr
