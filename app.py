# app.py
import streamlit as st
import streamlit.components.v1 as components
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from PIL import Image
import io
import random
import pandas as pd

# ===== KONSTANTA =====
HEADER_BYTES = 11
HEADER_BITS = HEADER_BYTES * 8
MAX_SHOW_PIXELS = 300

# ===== DARK MODE GLOBAL =====
st.markdown(
    """
<style>
html, body, .stApp { background-color: #0e1117 !important; color: white !important; }
* { color: white !important; }
.stButton>button { background-color: #1f6feb; color: white !important; border-radius: 8px; }
.stButton>button:hover { background-color: #388bfd; }
</style>
""",
    unsafe_allow_html=True,
)

# ======================================================
# 🎉 SPLASH SCREEN HALAMAN AWAL
# ======================================================

if "show_home" not in st.session_state:
    st.session_state["show_home"] = True

if st.session_state["show_home"]:
    st.markdown(
        """
        <div style="
            padding: 30px;
            background-color: #11151c;
            border-radius: 15px;
            border: 1px solid rgba(255,255,255,0.10);
            text-align: center;
            margin-top: 30px;
        ">
            <h1 style="color:white; margin-bottom:10px; font-size:32px;">
                📘 LAPORAN PROJECT KRIPTOGRAFI DAN STEGANOGRAFI
            </h1>

            <h2 style="color:#4ba3ff; margin-top:0; font-size:25px;">
                SISTEM PENGAMANAN SEED PHRASE MENGGUNAKAN KOMBINASI<br>
                ALGORITMA KRIPTOGRAFI RSA DAN STEGANOGRAFI LSB
            </h2>

            <hr style="width:70%; border: 1px solid rgba(255,255,255,0.12); margin: 30px auto;">

            <h3 style="color:white; font-size:20px; margin-bottom:8px;">
                Dosen Pengampu:
            </h3>
            <p style="color:#cccccc; font-size:17px;">
                Ida Ayu Gde Suwiprabayanti Putra, S.Kom., M.T.
            </p>

            <br>

            <h3 style="color:white; font-size:20px; margin-bottom:8px;">
                Oleh:<br>Kelompok 3
            </h3>

            <table style="margin-left:auto; margin-right:auto; color:white; font-size:17px; text-align:left;">
                <tr><td>Raihan Akbar Maulana</td><td style="padding-left:20px;">2208561001</td></tr>
                <tr><td>I Made Chandra Widjaya</td><td style="padding-left:20px;">2208561009</td></tr>
                <tr><td>I Putu Herdy Juniawan</td><td style="padding-left:20px;">2208561033</td></tr>
                <tr><td>I Kadek Adi Sentana</td><td style="padding-left:20px;">2208561138</td></tr>
            </table>

            <br><br>

            <button style="
                background-color:#1f6feb;
                padding:12px 22px;
                font-size:16px;
                color:white;
                border:none;
                border-radius:8px;
                cursor:pointer;
            " onclick="window.location.href='/?run=1'">
                ▶️ Masuk ke Program
            </button>

        </div>
        """,
        unsafe_allow_html=True,
    )
    st.stop()

# ======================================================
# APP TITLE NORMAL SETELAH MASUK MENU
# ======================================================
st.set_page_config(page_title="RSA + LSB Stego", layout="wide")
st.title("🔐 RSA + LSB Steganografi")

# ===== UI PREMIUM: SCROLLABLE TABLE =====
def scrollable_table(df: pd.DataFrame, height: int = 260):
    """Render pandas DataFrame as an HTML table inside a dark scrollable container."""
    if df is None or df.empty:
        st.info("📭 Tidak ada data untuk ditampilkan")
        return

    table_html = df.to_html(index=False, classes="nice-table", escape=False)

    html = f"""
    <html><head><style>
        .table-wrapper {{
            max-height: {height}px;
            overflow-y: auto;
            overflow-x: auto;
            border-radius: 10px;
            border: 1px solid rgba(255,255,255,0.12);
            background-color: #0e1117;
            padding: 6px;
        }}
        table.nice-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            background-color: #0e1117;
            color: white;
        }}
        table.nice-table thead th {{
            position: sticky;
            top: 0;
            background-color: #1a1d23;
            padding: 8px;
            font-weight: 600;
            border-bottom: 1px solid rgba(255,255,255,0.18);
        }}
        table.nice-table td {{
            padding: 8px;
            border-bottom: 1px solid rgba(255,255,255,0.06);
        }}
        table.nice-table tr:nth-child(even) td {{
            background-color: #11151c !important;
        }}
        table.nice-table tr:hover td {{
            background-color: #1b1f26 !important;
        }}
    </style></head>
    <body>
        <div class="table-wrapper">{table_html}</div>
    </body></html>
    """

    components.html(html, height=height + 40, scrolling=True)

# ===== RSA HELPERS =====
def generate_rsa_keypair(bits: int = 2048):
    key = RSA.generate(bits)
    return key.export_key(), key.publickey().export_key()


def rsa_encrypt(pub, data_bytes: bytes) -> bytes:
    return PKCS1_OAEP.new(pub).encrypt(data_bytes)


def rsa_decrypt(priv, ciphertext: bytes) -> bytes:
    return PKCS1_OAEP.new(priv).decrypt(ciphertext)

# ===== BIT OPS =====
def _to_bitstring(b: bytes) -> str:
    return "".join(f"{x:08b}" for x in b)


def _from_bitstring(s: str) -> bytes:
    return bytes(int(s[i : i + 8], 2) for i in range(0, len(s), 8))


def int_to_bytes_be(n: int, length: int) -> bytes:
    return n.to_bytes(length, "big")


def build_header_bits(random_flag: bool, seed: int, msg_bits: int) -> str:
    b = bytearray()
    b.extend(b"ST")
    b.append(1 if random_flag else 0)
    b.extend(int_to_bytes_be(seed & 0xFFFFFFFF, 4))
    b.extend(int_to_bytes_be(msg_bits & 0xFFFFFFFF, 4))
    return "".join(format(x, "08b") for x in b)


def parse_header_from_bits(bitstr: str):
    if len(bitstr) < HEADER_BITS:
        return None
    bs = bytearray(int(bitstr[i : i + 8], 2) for i in range(0, HEADER_BITS, 8))
    if bs[:2] != b"ST":
        return None
    return {
        "random": bool(bs[2] & 1),
        "seed": int.from_bytes(bs[3:7], "big"),
        "msg_len_bits": int.from_bytes(bs[7:11], "big"),
    }

# ===== IMAGE OPS =====
def coords_from_index(idx: int, width: int):
    return idx % width, idx // width


def embed_ciphertext_into_channel(img: Image.Image, ciphertext: bytes, channel: str, use_random: bool, seed=None):
    if img.mode != "RGB":
        img = img.convert("RGB")

    w, h = img.size
    total = w * h
    ch = {"R": 0, "G": 1, "B": 2}[channel]

    msg_bits = _to_bitstring(ciphertext)
    nbits = len(msg_bits)

    # seed
    if use_random:
        seed = random.getrandbits(32) if seed is None else int(seed)
    else:
        seed = 0

    header_bits = build_header_bits(use_random, seed, nbits)

    if nbits > total - HEADER_BITS:
        raise ValueError("Pesan terlalu besar untuk disisipkan pada gambar ini.")

    px = list(img.getdata())
    mod = list(px)

    # header
    for i, b in enumerate(header_bits):
        bit = int(b)
        p = list(mod[i])
        p[ch] = (p[ch] & ~1) | bit
        mod[i] = tuple(p)

    available = list(range(HEADER_BITS, total))
    if use_random:
        rng = random.Random(seed)
        pos = rng.sample(available, nbits)
    else:
        pos = available[:nbits]

    changes = []
    for i, position in enumerate(pos):
        bit = int(msg_bits[i])
        p = list(mod[position])
        old = p[ch]
        new = (old & ~1) | bit
        p[ch] = new
        mod[position] = tuple(p)
        changes.append(
            {
                "bit_index": i,
                "pos": position,
                "coord": coords_from_index(position, w),
                "inserted_bit": bit,
                "old_pixel": px[position],
                "new_pixel": mod[position],
                "old_lsb": old & 1,
                "new_lsb": new & 1,
            }
        )

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
        "changes": changes,
    }


def extract_bits_from_channel(img: Image.Image, ch: int):
    px = list(img.getdata())

    header_bits = "".join(str(px[i][ch] & 1) for i in range(HEADER_BITS))
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

    bits = "".join(str(px[p][ch] & 1) for p in pos)
    return header, bits, pos

# ======================================================
# STREAMLIT MENU
# ======================================================
menu = st.sidebar.selectbox("Menu", ["Generate Key", "Enkripsi + Stego", "Ekstrak + Dekripsi"])

# ======================================================
# 1. GENERATE KEY
# ======================================================
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


# ======================================================
# 2. ENKRIPSI + STEGO
# ======================================================
elif menu == "Enkripsi + Stego":

    st.header("🧩 Enkripsi Seed Phrase → RSA → LSB")

    with st.form("encrypt_form"):
        col1, col2 = st.columns([2, 1])

        with col1:
            msg = st.text_area("Seed phrase / pesan:", height=120)
            pubfile = st.file_uploader("Upload Public Key (PEM)", type=["pem"])
            cover = st.file_uploader("Upload Cover Image (PNG)", type=["png"])

        with col2:
            channel = st.radio("Pilih channel LSB:", ["R", "G", "B"])
            use_random = st.checkbox("Gunakan Mode Random?")
            seed_input = st.text_input("Seed (opsional, integer)", "")
            show_all = st.checkbox("Tampilkan semua perubahan pixel?")

        ok = st.form_submit_button("Mulai Enkripsi")

    if ok:
        try:
            if not msg or pubfile is None or cover is None:
                st.error("Lengkapi pesan, public key, dan gambar cover terlebih dahulu.")
            else:
                pub = RSA.import_key(pubfile.read())
                ciphertext = rsa_encrypt(pub, msg.encode())

                seed_val = int(seed_input) if (use_random and seed_input.strip() != "") else None

                img = Image.open(cover)
                stego_buf, summary = embed_ciphertext_into_channel(
                    img, ciphertext, channel, use_random, seed_val
                )
                summary["file_name"] = getattr(cover, "name", "cover")

                st.success("Berhasil disisipkan ke dalam gambar! 🎉")
                st.image(stego_buf, width=350)

                st.download_button(
                    "Download Stego Image",
                    stego_buf.getvalue(),
                    f"{summary['file_name']}_stego.png",
                    mime="image/png",
                )

                # ----- Ringkasan -----
                st.subheader("📌 Ringkasan Penyisipan")
                st.write(f"File input : **{summary['file_name']}**")
                st.write(f"Channel    : **{summary['channel']}**")
                st.write(f"Mode RANDOM : **{'YA' if summary['use_random'] else 'TIDAK'}**")
                if summary["use_random"]:
                    st.write(f"Seed (32-bit): **{summary['seed']}**")
                st.write(f"Jumlah bit pesan : **{summary['nbits']}**")
                st.write(f"Ciphertext byte length : **{summary['ciphertext_bytes_len']}**")

                # Ciphertext table
                ct_table = []
                for i, b in enumerate(ciphertext):
                    char = chr(b) if 32 <= b <= 126 else "·"
                    ct_table.append(
                        {"index": i, "ascii_code": b, "char": char, "hex": f"{b:02x}", "bin": f"{b:08b}"}
                    )

                st.markdown("### 🔸 Ciphertext per-byte")
                scrollable_table(pd.DataFrame(ct_table), height=260)

                # Pixel changes
                rows = summary["changes"]
                showN = len(rows) if show_all else min(len(rows), HEADER_BITS)
                pixel_table = []
                for i in range(showN):
                    r = rows[i]
                    pixel_table.append(
                        {
                            "no": i + 1,
                            "index": r["pos"],
                            "coord": str(r["coord"]),
                            "bit": r["inserted_bit"],
                            "old_pixel": str(r["old_pixel"]),
                            "new_pixel": str(r["new_pixel"]),
                            "old_lsb": r["old_lsb"],
                            "new_lsb": r["new_lsb"],
                        }
                    )

                st.markdown("### 🔸 Perubahan Pixel (LSB)")
                scrollable_table(pd.DataFrame(pixel_table), height=300)

        except Exception as e:
            st.error(f"❌ Error saat enkripsi/embed: {e}")

# ======================================================
# 3. EKSTRAK + DEKRIPSI
# ======================================================
elif menu == "Ekstrak + Dekripsi":

    st.header("🕵️ Ekstrak ciphertext (header-aware) & Dekripsi RSA")

    decode_mode = st.radio(
        "Pilih mode decode",
        ["Normal (stego + private key)", "Random (cover + stego + private key)"],
    )

    # ------------------------ NORMAL ------------------------
    if decode_mode.startswith("Normal"):
        col1, col2 = st.columns(2)
        with col1:
            uploaded_stego = st.file_uploader(
                "Upload Stego Image (PNG)", type=["png"], key="stego_only"
            )
        with col2:
            uploaded_priv = st.file_uploader(
                "Upload Private Key (PEM)", type=["pem"], key="priv_only"
            )

        if st.button("Ekstrak & Dekripsi (Normal)"):
            try:
                if uploaded_stego is None or uploaded_priv is None:
                    st.error("Upload stego image dan private key terlebih dahulu.")
                else:
                    stego_img = Image.open(uploaded_stego)
                    priv = RSA.import_key(uploaded_priv.read())

                    found = False
                    for ch_index, cname in enumerate(["R", "G", "B"]):
                        header, bits, positions = extract_bits_from_channel(
                            stego_img, ch_index
                        )
                        if header is None:
                            continue

                        if header["random"]:
                            st.error(
                                f"Header ditemukan di channel {cname} tetapi RANDOM=YA."
                                "Gunakan mode RANDOM untuk decode."
                            )
                            found = True
                            break

                        ciphertext_bytes = _from_bitstring(bits)
                        decrypted = rsa_decrypt(priv, ciphertext_bytes)

                        st.success(
                            f"Header ditemukan pada channel {cname} (NON-RANDOM). "
                            "Pesan berhasil didekripsi."
                        )
                        st.subheader("Seed Phrase / Pesan:")
                        st.code(decrypted.decode())

                        # ciphertext table
                        ct_rows = []
                        for i, b in enumerate(ciphertext_bytes):
                            char = chr(b) if 32 <= b <= 126 else "·"
                            ct_rows.append(
                                {"index": i, "ascii_code": b, "char": char, "hex": f"{b:02x}", "bin": f"{b:08b}"}
                            )

                        st.markdown("### 🔸 Ciphertext per-byte")
                        scrollable_table(pd.DataFrame(ct_rows), height=260)

                        found = True
                        break

                    if not found:
                        st.error("Header tidak ditemukan di semua channel.")

            except Exception as e:
                st.error(f"❌ Error saat ekstraksi/dekripsi: {e}")

    # ------------------------ RANDOM ------------------------
    else:
        col1, col2, col3 = st.columns(3)
        with col1:
            uploaded_cover = st.file_uploader("Upload Cover Image (PNG)", type=["png"], key="cover")
        with col2:
            uploaded_stego = st.file_uploader("Upload Stego Image (PNG)", type=["png"], key="stego")
        with col3:
            uploaded_priv = st.file_uploader("Upload Private Key (PEM)", type=["pem"], key="priv")

        if st.button("Ekstrak & Dekripsi (Random)"):
            try:
                if uploaded_cover is None or uploaded_stego is None or uploaded_priv is None:
                    st.error("Upload cover, stego, dan private key terlebih dahulu.")
                else:
                    cover = Image.open(uploaded_cover)
                    stego_img = Image.open(uploaded_stego)
                    if cover.size != stego_img.size:
                        st.error("Cover dan stego harus sama ukuran.")
                    else:
                        priv = RSA.import_key(uploaded_priv.read())

                        found = False
                        for ch_index, cname in enumerate(["R", "G", "B"]):
                            header, bits, positions = extract_bits_from_channel(
                                stego_img, ch_index
                            )
                            if header is None:
                                continue

                            ciphertext_bytes = _from_bitstring(bits)
                            decrypted = rsa_decrypt(priv, ciphertext_bytes)

                            st.success(
                                f"Header ditemukan pada channel {cname}:"
                            )
                            st.write(f"- Mode RANDOM: {'YA' if header['random'] else 'TIDAK'}")
                            if header["random"]:
                                st.write(f"- Seed: {header['seed']}")
                            st.write(f"- Panjang pesan (bit): {header['msg_len_bits']}")
                            st.subheader("Seed Phrase / Pesan:")
                            st.code(decrypted.decode())

                            # pixel diffs
                            pixels_cover = list(cover.getdata())
                            pixels_stego = list(stego_img.getdata())
                            diffs = []
                            for i, p in enumerate(positions[:MAX_SHOW_PIXELS]):
                                cv = pixels_cover[p][ch_index]
                                sv = pixels_stego[p][ch_index]
                                diffs.append(
                                    {
                                        "no": i + 1,
                                        "idx": p,
                                        "coord": coords_from_index(p, cover.size[0]),
                                        "cover_val": cv,
                                        "stego_val": sv,
                                        "old_lsb": cv & 1,
                                        "new_lsb": sv & 1,
                                        "inserted_bit": sv & 1,
                                    }
                                )

                            st.markdown("### 🔸 Perubahan Pixel (Random Mode)")
                            scrollable_table(pd.DataFrame(diffs), height=300)

                            # ciphertext view
                            byte_rows = []
                            for i, b in enumerate(ciphertext_bytes):
                                char = chr(b) if 32 <= b <= 126 else "·"
                                byte_rows.append(
                                    {"index": i, "ascii_code": b, "char": char, "hex": f"{b:02x}", "bin": f"{b:08b}"}
                                )

                            st.subheader("Ciphertext per-byte")
                            scrollable_table(pd.DataFrame(byte_rows), height=260)

                            found = True
                            break

                        if not found:
                            st.error("Header tidak ditemukan, pastikan file benar.")

            except Exception as e:
                st.error(f"❌ Error saat ekstraksi/dekripsi random: {e}")
