#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_aes.py
=============
Skrip verifikasi independen untuk AES-128 (satu blok, mode ECB).

Tujuan skrip ini:
  1. Menjadi implementasi AES-128 KEDUA yang berdiri sendiri (murni Python,
     tanpa library kriptografi), sehingga hasil dari aplikasi web (JavaScript)
     dapat dicocokkan / diverifikasi silang secara independen.
  2. Opsional: jika package pihak ketiga `pycryptodome` terpasang, skrip ini
     juga akan mencocokkan hasil dengan library standar tersebut — sesuai
     ketentuan tugas bahwa library pihak ketiga HANYA boleh dipakai untuk
     verifikasi, bukan sebagai implementasi utama.

Cara pakai:
    python verify_aes.py --key <32 hex> --text "PLAINTEXT" --mode encrypt
    python verify_aes.py --key <32 hex> --hex  <32 hex plaintext> --mode encrypt
    python verify_aes.py --key <32 hex> --hex  <32 hex ciphertext> --mode decrypt
    python verify_aes.py --selftest        # menjalankan test vector FIPS-197

Contoh:
    python verify_aes.py --key 000102030405060708090a0b0c0d0e0f \
                          --hex 00112233445566778899aabbccddeeff \
                          --mode encrypt
"""

import argparse
import sys

# =============================================================================
# 1. Tabel referensi
# =============================================================================
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


# =============================================================================
# 2. Util
# =============================================================================
def hex_to_bytes(h):
    h = h.strip().replace(" ", "")
    return list(bytes.fromhex(h))


def bytes_to_hex(b):
    return bytes(b).hex().upper()


def text_to_bytes16(text):
    b = list(text.encode("utf-8"))[:16]
    b += [0x00] * (16 - len(b))
    return b


def bytes_to_matrix(b):
    """byte[16] -> matrix 4x4 column-major: m[r][c] = b[c*4+r]"""
    return [[b[c * 4 + r] for c in range(4)] for r in range(4)]


def matrix_to_bytes(m):
    b = [0] * 16
    for c in range(4):
        for r in range(4):
            b[c * 4 + r] = m[r][c]
    return b


def matrix_to_hex(m):
    return bytes_to_hex(matrix_to_bytes(m))


def clone(m):
    return [row[:] for row in m]


# =============================================================================
# 3. GF(2^8)
# =============================================================================
def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p & 0xFF


# =============================================================================
# 4. Transformasi dasar
# =============================================================================
def sub_bytes(m, inverse=False):
    box = INV_SBOX if inverse else SBOX
    return [[box[m[r][c]] for c in range(4)] for r in range(4)]


def shift_rows(m, inverse=False):
    out = clone(m)
    for r in range(1, 4):
        row = m[r]
        out[r] = [row[(c - r) % 4] if inverse else row[(c + r) % 4] for c in range(4)]
    return out


MIX_FWD = [[0x02, 0x03, 0x01, 0x01], [0x01, 0x02, 0x03, 0x01], [0x01, 0x01, 0x02, 0x03], [0x03, 0x01, 0x01, 0x02]]
MIX_INV = [[0x0E, 0x0B, 0x0D, 0x09], [0x09, 0x0E, 0x0B, 0x0D], [0x0D, 0x09, 0x0E, 0x0B], [0x0B, 0x0D, 0x09, 0x0E]]


def mix_columns(m, inverse=False):
    M = MIX_INV if inverse else MIX_FWD
    out = [[0] * 4 for _ in range(4)]
    for c in range(4):
        col = [m[0][c], m[1][c], m[2][c], m[3][c]]
        for r in range(4):
            out[r][c] = gmul(M[r][0], col[0]) ^ gmul(M[r][1], col[1]) ^ gmul(M[r][2], col[2]) ^ gmul(M[r][3], col[3])
    return out


def add_round_key(m, rk):
    return [[m[r][c] ^ rk[r][c] for c in range(4)] for r in range(4)]


# =============================================================================
# 5. Key Expansion
# =============================================================================
def rot_word(w):
    return [w[1], w[2], w[3], w[0]]


def sub_word(w):
    return [SBOX[b] for b in w]


def key_expansion(key_bytes):
    words = [[key_bytes[4 * i + j] for j in range(4)] for i in range(4)]
    for i in range(4, 44):
        temp = words[i - 1][:]
        if i % 4 == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= RCON[i // 4]
        words.append([words[i - 4][j] ^ temp[j] for j in range(4)])

    round_keys = []
    for rk in range(11):
        w = words[rk * 4:rk * 4 + 4]
        flat = [b for word in w for b in word]
        round_keys.append(bytes_to_matrix(flat))
    return words, round_keys


# =============================================================================
# 6. Encrypt / Decrypt (satu blok, 128-bit)
# =============================================================================
def aes128_encrypt_block(plain_bytes, key_bytes):
    _, round_keys = key_expansion(key_bytes)
    state = bytes_to_matrix(plain_bytes)

    state = add_round_key(state, round_keys[0])
    for rnd in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[rnd])
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])

    return matrix_to_bytes(state)


def aes128_decrypt_block(cipher_bytes, key_bytes):
    _, round_keys = key_expansion(key_bytes)
    state = bytes_to_matrix(cipher_bytes)

    state = add_round_key(state, round_keys[10])
    for rnd in range(9, 0, -1):
        state = shift_rows(state, inverse=True)
        state = sub_bytes(state, inverse=True)
        state = add_round_key(state, round_keys[rnd])
        state = mix_columns(state, inverse=True)
    state = shift_rows(state, inverse=True)
    state = sub_bytes(state, inverse=True)
    state = add_round_key(state, round_keys[0])

    return matrix_to_bytes(state)


# =============================================================================
# 7. Verifikasi silang opsional dengan pycryptodome (jika tersedia)
# =============================================================================
def cross_check_pycryptodome(plain_bytes, key_bytes, mode):
    try:
        from Crypto.Cipher import AES as PyAES
    except ImportError:
        return None  # pycryptodome tidak terpasang -> lewati, bukan error

    cipher = PyAES.new(bytes(key_bytes), PyAES.MODE_ECB)
    if mode == "encrypt":
        return list(cipher.encrypt(bytes(plain_bytes)))
    else:
        return list(cipher.decrypt(bytes(plain_bytes)))


# =============================================================================
# 8. Self-test dengan test vector resmi (FIPS-197 & contoh Rijndael)
# =============================================================================
def self_test():
    vectors = [
        {
            "name": "FIPS-197 Appendix B",
            "key": "000102030405060708090a0b0c0d0e0f",
            "plaintext": "00112233445566778899aabbccddeeff",
            "ciphertext": "69C4E0D86A7B0430D8CDB78070B4C55A",
        },
        {
            "name": "Rijndael animation example",
            "key": "2b7e151628aed2a6abf7158809cf4f3c",
            "plaintext": "3243f6a8885a308d313198a2e0370734",
            "ciphertext": "3925841D02DC09FBDC118597196A0B32",
        },
    ]
    all_ok = True
    print("=" * 70)
    print("SELF-TEST — mencocokkan implementasi dengan test vector resmi")
    print("=" * 70)
    for v in vectors:
        key = hex_to_bytes(v["key"])
        pt = hex_to_bytes(v["plaintext"])
        ct = aes128_encrypt_block(pt, key)
        ct_hex = bytes_to_hex(ct)
        ok = ct_hex == v["ciphertext"]
        all_ok = all_ok and ok
        print(f"\n[{v['name']}]")
        print(f"  Key        : {v['key']}")
        print(f"  Plaintext  : {v['plaintext']}")
        print(f"  Ciphertext : {ct_hex}")
        print(f"  Expected   : {v['ciphertext']}")
        print(f"  Status     : {'LULUS ✔' if ok else 'GAGAL ✘'}")

        # round-trip decrypt check
        pt_back = bytes_to_hex(aes128_decrypt_block(hex_to_bytes(ct_hex), key))
        rt_ok = pt_back == v["plaintext"].upper()
        all_ok = all_ok and rt_ok
        print(f"  Dekripsi balik menghasilkan plaintext semula : {'LULUS ✔' if rt_ok else 'GAGAL ✘'}")

    print("\n" + "=" * 70)
    print("HASIL AKHIR SELF-TEST:", "SEMUA LULUS ✔" if all_ok else "ADA YANG GAGAL ✘")
    print("=" * 70)
    return all_ok


# =============================================================================
# 9. CLI
# =============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="Verifikasi independen AES-128 (satu blok, mode ECB) — untuk mencocokkan hasil aplikasi web."
    )
    parser.add_argument("--key", help="Kunci AES-128, 32 karakter hex (16 byte)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--text", help="Plaintext berupa teks biasa (maks 16 karakter, akan di-pad 0x00)")
    group.add_argument("--hex", help="Plaintext/ciphertext dalam format hex 32 karakter (16 byte)")
    parser.add_argument("--mode", choices=["encrypt", "decrypt"], default="encrypt", help="Mode operasi")
    parser.add_argument("--selftest", action="store_true", help="Jalankan self-test dengan test vector resmi")
    args = parser.parse_args()

    if args.selftest:
        ok = self_test()
        sys.exit(0 if ok else 1)

    if not args.key:
        parser.error("--key wajib diisi (kecuali menjalankan --selftest)")
    if len(args.key) != 32:
        parser.error("--key harus tepat 32 karakter hex (16 byte)")
    key_bytes = hex_to_bytes(args.key)

    if args.mode == "encrypt":
        if args.text:
            if len(args.text) > 16:
                parser.error("--text maksimal 16 karakter")
            in_bytes = text_to_bytes16(args.text)
        elif args.hex:
            if len(args.hex) != 32:
                parser.error("--hex plaintext harus 32 karakter (16 byte)")
            in_bytes = hex_to_bytes(args.hex)
        else:
            parser.error("Isi salah satu dari --text atau --hex untuk plaintext")

        result = aes128_encrypt_block(in_bytes, key_bytes)
        result_hex = bytes_to_hex(result)
        print(f"Plaintext (hex) : {bytes_to_hex(in_bytes)}")
        print(f"Key             : {args.key.upper()}")
        print(f"Ciphertext      : {result_hex}")

        ref = cross_check_pycryptodome(in_bytes, key_bytes, "encrypt")
        if ref is not None:
            match = bytes_to_hex(ref) == result_hex
            print(f"Cross-check pycryptodome : {bytes_to_hex(ref)}  ->  {'COCOK ✔' if match else 'TIDAK COCOK ✘'}")
        else:
            print("(pycryptodome tidak terpasang — cross-check dilewati; install dengan `pip install pycryptodome` bila ingin verifikasi tambahan)")

    else:
        if not args.hex or len(args.hex) != 32:
            parser.error("--hex ciphertext (32 karakter) wajib diisi untuk mode decrypt")
        ct_bytes = hex_to_bytes(args.hex)
        result = aes128_decrypt_block(ct_bytes, key_bytes)
        result_hex = bytes_to_hex(result)
        as_text = "".join(chr(b) if 32 <= b <= 126 else "." for b in result)
        print(f"Ciphertext (hex) : {args.hex.upper()}")
        print(f"Key              : {args.key.upper()}")
        print(f"Plaintext (hex)  : {result_hex}")
        print(f"Plaintext (teks) : \"{as_text}\"")

        ref = cross_check_pycryptodome(ct_bytes, key_bytes, "decrypt")
        if ref is not None:
            match = bytes_to_hex(ref) == result_hex
            print(f"Cross-check pycryptodome : {bytes_to_hex(ref)}  ->  {'COCOK ✔' if match else 'TIDAK COCOK ✘'}")
        else:
            print("(pycryptodome tidak terpasang — cross-check dilewati; install dengan `pip install pycryptodome` bila ingin verifikasi tambahan)")


if __name__ == "__main__":
    main()
