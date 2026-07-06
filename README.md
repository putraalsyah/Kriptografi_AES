# AES-128 Cipher Visualizer

Aplikasi web simulasi algoritma **Advanced Encryption Standard (AES-128)** yang menampilkan proses enkripsi maupun dekripsi secara lengkap dan rinci — mulai dari Key Expansion, State Matrix tiap ronde, hingga hasil akhir — untuk keperluan pembelajaran mata kuliah Kriptografi.

Dibangun murni dengan **HTML, CSS, dan JavaScript vanilla** (tanpa framework, tanpa library kriptografi pihak ketiga). Seluruh logika AES (SubBytes, ShiftRows, MixColumns, AddRoundKey, Key Expansion, beserta operasi inversnya) diimplementasikan sendiri dari nol.

🔗 **Live demo:** [https://www.aesputraaliansyah.my.id](https://aesputraaliansyah.my.id)

---

## Daftar Isi

- [Fitur](#fitur)
- [Struktur File](#struktur-file)
- [Cara Menjalankan Aplikasi](#cara-menjalankan-aplikasi)
- [Cara Menggunakan Aplikasi](#cara-menggunakan-aplikasi)
  - [1. Enkripsi](#1-enkripsi)
  - [2. Dekripsi](#2-dekripsi)
  - [3. Melihat Detail Perhitungan](#3-melihat-detail-perhitungan)
- [Verifikasi Hasil dengan Python](#verifikasi-hasil-dengan-python)
- [Parameter Teknis](#parameter-teknis)
- [Batasan Aplikasi](#batasan-aplikasi)
- [Referensi](#referensi)

---

## Fitur

- Enkripsi & dekripsi AES-128 untuk satu blok data (128-bit / 16 byte), mode ECB.
- Input plaintext berupa **teks bebas** (maks. 16 karakter, otomatis di-padding `0x00`) atau **hex 32 karakter**.
- Visualisasi **Key Expansion** lengkap: State awal kunci, seluruh word `W[0]` s/d `W[43]`, detail fungsi `g` (RotWord → SubWord → XOR Rcon) untuk setiap word kelipatan 4, dan seluruh Round Key `RK0`–`RK10`.
- Visualisasi **Initial Round**, **Round 1–9** (SubBytes, ShiftRows, MixColumns, AddRoundKey — masing-masing sebelum/sesudah), dan **Round 10** (final round tanpa MixColumns).
- Visualisasi alur **dekripsi** lengkap (AddRoundKey → InvShiftRows → InvSubBytes → AddRoundKey → InvMixColumns per ronde, hingga final round).
- Setiap State Matrix ditampilkan sebagai tabel 4×4 hex dengan **highlight** pada byte yang berubah nilai.
- Section tiap ronde bisa **expand/collapse**, dilengkapi **side navigation** untuk lompat langsung ke ronde tertentu.
- Toggle untuk menampilkan/menyembunyikan seluruh detail proses.
- Validasi input (panjang karakter, format hex) dengan pesan error yang jelas.
- Tombol salin hasil (ciphertext/plaintext) ke clipboard.
- Desain responsif — dapat digunakan di desktop maupun mobile.

---

## Struktur File

```
aes-simulator/
├── index.html       # Struktur halaman & form
├── style.css        # Seluruh styling antarmuka
├── aes-core.js       # Implementasi inti algoritma AES-128 (murni, tanpa library)
├── ui.js             # Penghubung antara aes-core.js dengan tampilan (render tabel, validasi, event)
└── verify_aes.py     # Skrip Python independen untuk cross-check hasil aplikasi
```

---

## Cara Menjalankan Aplikasi

Aplikasi ini **client-side sepenuhnya** (tidak butuh server/backend), sehingga bisa dijalankan dengan cara:

### Opsi A — Langsung dibuka di browser
Klik dua kali file `index.html`, atau buka melalui `File > Open` di browser (Chrome/Edge/Firefox terbaru direkomendasikan).

### Opsi B — Local server (opsional, untuk menghindari batasan file:// pada beberapa browser)
```bash
# Python
python -m http.server 8000

# atau Node.js
npx serve .
```
Lalu buka `http://localhost:8000` di browser.

### Opsi C — Hosting ke domain `.my.id`
Upload ketiga file (`index.html`, `style.css`, `aes-core.js`, `ui.js`) ke hosting/static site Anda (Netlify, GitHub Pages, Vercel, cPanel, dsb.) yang sudah terhubung ke domain `.my.id` sesuai ketentuan tugas. Tidak ada dependency build/install — cukup upload apa adanya.

Aplikasi ini sudah di-hosting dan dapat diakses langsung di: **[https://aesputraaliansyah.my.id](https://aesputraaliansyah.my.id)**

---

## Cara Menggunakan Aplikasi

### 1. Enkripsi

1. Pilih **Mode Operasi → Enkripsi** (default).
2. Pilih format plaintext:
   - **Teks** — ketik teks bebas maksimal 16 karakter (contoh: `HELLO AES-128!!`). Jika kurang dari 16 karakter, sisanya otomatis diisi byte `00`.
   - **Hex** — masukkan 32 karakter heksadesimal (contoh: `3243f6a8885a308d313198a2e0370734`).
3. Masukkan **Kunci AES-128** sebagai 32 karakter hex (16 byte), contoh: `000102030405060708090a0b0c0d0e0f`.
4. Klik **JALANKAN ENKRIPSI**.
5. Hasil **ciphertext** (format hex) akan muncul di panel "Hasil". Klik **SALIN HASIL** untuk menyalin ke clipboard.

### 2. Dekripsi

1. Pilih **Mode Operasi → Dekripsi**.
2. Masukkan **Ciphertext** sebagai 32 karakter hex.
3. Masukkan **Kunci AES-128** yang sama (32 karakter hex).
4. Klik **JALANKAN DEKRIPSI**.
5. Hasil **plaintext** (format hex, beserta representasi teks bila karakternya tercetak) akan muncul di panel "Hasil".

### 3. Melihat Detail Perhitungan

- Pastikan toggle **"Tampilkan detail perhitungan step-by-step"** dalam keadaan aktif (default: aktif).
- Setelah menjalankan enkripsi/dekripsi, panel **"Detail Proses Perhitungan"** akan muncul di bagian bawah, berisi:
  - **Key Expansion** — klik `lihat fungsi g()` pada word tertentu untuk melihat rincian RotWord/SubWord/XOR Rcon.
  - **Initial Round**, **Round 1–10** (atau ronde untuk dekripsi) — setiap section dapat di-klik pada judulnya untuk expand/collapse.
  - Gunakan **navigasi di sisi kiri** (side navigation) untuk lompat langsung ke ronde tertentu.
  - Sel State Matrix yang nilainya berubah dari step sebelumnya akan otomatis di-highlight.
- Nonaktifkan toggle bila hanya ingin melihat hasil akhir tanpa rincian proses.

---

## Verifikasi Hasil dengan Python

File `verify_aes.py` adalah implementasi AES-128 kedua yang berdiri sendiri (murni Python, tanpa library), dipakai untuk mencocokkan hasil dari aplikasi web secara independen.

```bash
# Menjalankan self-test dengan test vector resmi (FIPS-197)
python verify_aes.py --selftest

# Enkripsi dengan plaintext teks
python verify_aes.py --key 000102030405060708090a0b0c0d0e0f --text "HELLO AES-128!!" --mode encrypt

# Enkripsi dengan plaintext hex
python verify_aes.py --key 000102030405060708090a0b0c0d0e0f --hex 00112233445566778899aabbccddeeff --mode encrypt

# Dekripsi
python verify_aes.py --key 000102030405060708090a0b0c0d0e0f --hex 69c4e0d86a7b0430d8cdb78070b4c55a --mode decrypt
```

> Opsional: bila Anda menginstal `pip install pycryptodome`, skrip ini juga akan otomatis mencocokkan hasil dengan library standar tersebut sebagai lapisan verifikasi tambahan (bukan sebagai implementasi utama).

---

## Parameter Teknis

| Parameter        | Nilai                                  |
|-------------------|-----------------------------------------|
| Ukuran blok        | 128-bit (16 byte)                       |
| Panjang kunci      | 128-bit (16 byte / 32 karakter hex)     |
| Jumlah ronde       | 10 ronde + 1 initial round              |
| Mode operasi       | ECB (Electronic Codebook), satu blok    |
| Format input       | Teks (maks. 16 karakter) atau hex 32 karakter; kunci hex 32 karakter |

---

## Batasan Aplikasi

- Hanya memproses **satu blok** data (16 byte) — belum mendukung mode operasi berantai (CBC, CTR, dll.) untuk data lebih dari satu blok.
- Plaintext teks yang lebih pendek dari 16 karakter di-padding dengan byte `0x00` (bukan skema padding standar seperti PKCS#7), khusus untuk keperluan simulasi/edukasi.
- Aplikasi ditujukan untuk pembelajaran cara kerja AES, bukan untuk penggunaan enkripsi produksi/keamanan nyata.

---

## Referensi

- NIST FIPS-197, *Advanced Encryption Standard (AES)*, 2001.
- Test vector resmi FIPS-197 Appendix B digunakan untuk validasi implementasi (`aes-core.js` dan `verify_aes.py`).
