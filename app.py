# app.py (FULL CODE UI PREMIUM)

import streamlit as st
import streamlit.components.v1 as components
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from PIL import Image
import io, random
import pandas as pd

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


# ===== STREAMLIT APP =====
st.set_page_config(page_title="RSA + LSB Stego", layout="wide")
st.title("🔐 RSA + LSB Steganografi")

menu = st.sidebar.selectbox("Menu", ["Generate Key", "Enkripsi + Stego", "Ekstrak + Dekripsi"])

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
