/* ============================================================================
   aes-core.js
   Implementasi AES-128 dari NOL (tanpa library kriptografi) untuk keperluan
   simulasi & edukasi. Setiap fungsi mencatat (log) State Matrix sebelum dan
   sesudah operasi agar dapat divisualisasikan pada antarmuka.

   Konvensi:
   - "matrix" = array 4x4 (matrix[row][col]), nilai byte 0-255, disusun
     column-major sesuai standar FIPS-197 (byte input mengisi kolom demi kolom).
   - Semua fungsi murni (pure) mengembalikan matrix BARU, tidak mengubah input,
     supaya before/after gampang dibandingkan.
   ========================================================================= */

const AES = (function () {
  "use strict";

  // ---------------------------------------------------------------------
  // 1. Tabel referensi (S-Box, Inverse S-Box, Rcon)
  // ---------------------------------------------------------------------
  const SBOX = [
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
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
  ];

  // Inverse S-Box dibangun otomatis dari SBOX (SBOX[x] = y  <=>  INV_SBOX[y] = x)
  const INV_SBOX = new Array(256);
  for (let i = 0; i < 256; i++) INV_SBOX[SBOX[i]] = i;

  // Rcon (byte pertama saja, 3 byte sisanya selalu 00) untuk word ke-1..10
  const RCON = [0x00, 0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36];

  // ---------------------------------------------------------------------
  // 2. Util dasar
  // ---------------------------------------------------------------------
  function hex2(n) { return n.toString(16).toUpperCase().padStart(2, "0"); }

  function hexToBytes(hex) {
    hex = hex.replace(/\s+/g, "");
    const out = [];
    for (let i = 0; i < hex.length; i += 2) out.push(parseInt(hex.substr(i, 2), 16));
    return out;
  }

  function bytesToHex(bytes) { return bytes.map(hex2).join(""); }

  function textToBytes16(text) {
    const bytes = [];
    for (let i = 0; i < text.length && bytes.length < 16; i++) bytes.push(text.charCodeAt(i) & 0xff);
    while (bytes.length < 16) bytes.push(0x00); // zero-padding sampai 16 byte
    return bytes;
  }

  // byte[16] -> matrix 4x4 column-major :  matrix[r][c] = byte[c*4 + r]
  function bytesToMatrix(bytes) {
    const m = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]];
    for (let c = 0; c < 4; c++)
      for (let r = 0; r < 4; r++)
        m[r][c] = bytes[c * 4 + r];
    return m;
  }

  function matrixToBytes(m) {
    const bytes = new Array(16);
    for (let c = 0; c < 4; c++)
      for (let r = 0; r < 4; r++)
        bytes[c * 4 + r] = m[r][c];
    return bytes;
  }

  function cloneMatrix(m) { return m.map(row => row.slice()); }

  function matrixToHex(m) { return bytesToHex(matrixToBytes(m)); }

  // ---------------------------------------------------------------------
  // 3. Operasi GF(2^8) — dibutuhkan MixColumns / InvMixColumns
  // ---------------------------------------------------------------------
  function gmul(a, b) {
    let p = 0;
    for (let i = 0; i < 8; i++) {
      if (b & 1) p ^= a;
      const hiBitSet = a & 0x80;
      a = (a << 1) & 0xff;
      if (hiBitSet) a ^= 0x1b; // reduksi modulo x^8+x^4+x^3+x+1 (0x11B)
      b >>= 1;
    }
    return p & 0xff;
  }

  // ---------------------------------------------------------------------
  // 4. Transformasi dasar AES
  // ---------------------------------------------------------------------
  function subBytes(m, inverse) {
    const box = inverse ? INV_SBOX : SBOX;
    const out = cloneMatrix(m);
    for (let r = 0; r < 4; r++)
      for (let c = 0; c < 4; c++)
        out[r][c] = box[m[r][c]];
    return out;
  }

  function shiftRows(m, inverse) {
    const out = cloneMatrix(m);
    for (let r = 1; r < 4; r++) {
      const row = m[r];
      const shifted = new Array(4);
      for (let c = 0; c < 4; c++) {
        const srcCol = inverse ? (c - r + 4) % 4 : (c + r) % 4;
        shifted[c] = row[srcCol];
      }
      out[r] = shifted;
    }
    return out;
  }

  function mixColumns(m, inverse) {
    const M = inverse
      ? [[0x0e,0x0b,0x0d,0x09],[0x09,0x0e,0x0b,0x0d],[0x0d,0x09,0x0e,0x0b],[0x0b,0x0d,0x09,0x0e]]
      : [[0x02,0x03,0x01,0x01],[0x01,0x02,0x03,0x01],[0x01,0x01,0x02,0x03],[0x03,0x01,0x01,0x02]];
    const out = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]];
    for (let c = 0; c < 4; c++) {
      const col = [m[0][c], m[1][c], m[2][c], m[3][c]];
      for (let r = 0; r < 4; r++) {
        out[r][c] = M[r][0]!==undefined ?
          (gmul(M[r][0], col[0]) ^ gmul(M[r][1], col[1]) ^ gmul(M[r][2], col[2]) ^ gmul(M[r][3], col[3])) : 0;
      }
    }
    return out;
  }

  function addRoundKey(m, rk) {
    const out = cloneMatrix(m);
    for (let r = 0; r < 4; r++)
      for (let c = 0; c < 4; c++)
        out[r][c] = m[r][c] ^ rk[r][c];
    return out;
  }

  // ---------------------------------------------------------------------
  // 5. Key Expansion (AES-128 -> 44 word -> 11 Round Key)
  // ---------------------------------------------------------------------
  function rotWord(w) { return [w[1], w[2], w[3], w[0]]; }
  function subWord(w) { return w.map(b => SBOX[b]); }

  function keyExpansion(keyBytes) {
    const words = []; // array of [b0,b1,b2,b3]
    for (let i = 0; i < 4; i++) {
      words.push([keyBytes[4*i], keyBytes[4*i+1], keyBytes[4*i+2], keyBytes[4*i+3]]);
    }

    const gLog = {}; // detail fungsi g, key = index word (kelipatan 4)

    for (let i = 4; i < 44; i++) {
      let temp = words[i - 1].slice();
      if (i % 4 === 0) {
        const afterRot = rotWord(temp);
        const afterSub = subWord(afterRot);
        const rconWord = [RCON[i / 4], 0x00, 0x00, 0x00];
        const afterXor = afterSub.map((b, idx) => b ^ rconWord[idx]);
        gLog[i] = {
          wordIndex: i,
          before: temp.slice(),
          afterRotWord: afterRot,
          afterSubWord: afterSub,
          rcon: rconWord,
          afterXorRcon: afterXor
        };
        temp = afterXor;
      }
      const newWord = words[i - 4].map((b, idx) => b ^ temp[idx]);
      words.push(newWord);
    }

    // Susun 11 Round Key (RK0..RK10), tiap RK = 4 word berurutan sbg kolom
    const roundKeys = [];
    for (let rk = 0; rk <= 10; rk++) {
      const w0 = words[rk*4], w1 = words[rk*4+1], w2 = words[rk*4+2], w3 = words[rk*4+3];
      const bytes = [...w0, ...w1, ...w2, ...w3];
      roundKeys.push(bytesToMatrix(bytes));
    }

    return { words, roundKeys, gLog };
  }

  // ---------------------------------------------------------------------
  // 6. Enkripsi lengkap dengan log setiap langkah
  // ---------------------------------------------------------------------
  function encrypt(plainBytes, keyBytes) {
    const { words, roundKeys, gLog } = keyExpansion(keyBytes);
    const steps = { keyExpansion: { initialKeyMatrix: bytesToMatrix(keyBytes), words, roundKeys, gLog }, rounds: [] };

    let state = bytesToMatrix(plainBytes);

    // Initial round
    const initialState = cloneMatrix(state);
    state = addRoundKey(state, roundKeys[0]);
    steps.initialRound = { stateIn: initialState, roundKeyUsed: roundKeys[0], stateOut: cloneMatrix(state) };

    // Round 1..9
    for (let round = 1; round <= 9; round++) {
      const stepLog = { round };
      stepLog.subBytes = { before: cloneMatrix(state) };
      state = subBytes(state, false);
      stepLog.subBytes.after = cloneMatrix(state);

      stepLog.shiftRows = { before: cloneMatrix(state) };
      state = shiftRows(state, false);
      stepLog.shiftRows.after = cloneMatrix(state);

      stepLog.mixColumns = { before: cloneMatrix(state) };
      state = mixColumns(state, false);
      stepLog.mixColumns.after = cloneMatrix(state);

      stepLog.addRoundKey = { before: cloneMatrix(state), roundKeyUsed: roundKeys[round] };
      state = addRoundKey(state, roundKeys[round]);
      stepLog.addRoundKey.after = cloneMatrix(state);

      steps.rounds.push(stepLog);
    }

    // Round 10 (final, tanpa MixColumns)
    const finalLog = { round: 10 };
    finalLog.subBytes = { before: cloneMatrix(state) };
    state = subBytes(state, false);
    finalLog.subBytes.after = cloneMatrix(state);

    finalLog.shiftRows = { before: cloneMatrix(state) };
    state = shiftRows(state, false);
    finalLog.shiftRows.after = cloneMatrix(state);

    finalLog.addRoundKey = { before: cloneMatrix(state), roundKeyUsed: roundKeys[10] };
    state = addRoundKey(state, roundKeys[10]);
    finalLog.addRoundKey.after = cloneMatrix(state);
    steps.rounds.push(finalLog);

    steps.ciphertext = matrixToHex(state);
    return { ciphertextHex: matrixToHex(state), steps };
  }

  // ---------------------------------------------------------------------
  // 7. Dekripsi lengkap (Inverse Cipher langsung / straightforward)
  // ---------------------------------------------------------------------
  function decrypt(cipherBytes, keyBytes) {
    const { words, roundKeys, gLog } = keyExpansion(keyBytes);
    const steps = { keyExpansion: { initialKeyMatrix: bytesToMatrix(keyBytes), words, roundKeys, gLog }, rounds: [] };

    let state = bytesToMatrix(cipherBytes);

    // AddRoundKey dengan RK10
    const initialState = cloneMatrix(state);
    state = addRoundKey(state, roundKeys[10]);
    steps.initialRound = { stateIn: initialState, roundKeyUsed: roundKeys[10], stateOut: cloneMatrix(state) };

    // Ronde 10 turun ke 1: InvShiftRows, InvSubBytes, AddRoundKey, InvMixColumns
    for (let round = 9; round >= 1; round--) {
      const stepLog = { round };

      stepLog.invShiftRows = { before: cloneMatrix(state) };
      state = shiftRows(state, true);
      stepLog.invShiftRows.after = cloneMatrix(state);

      stepLog.invSubBytes = { before: cloneMatrix(state) };
      state = subBytes(state, true);
      stepLog.invSubBytes.after = cloneMatrix(state);

      stepLog.addRoundKey = { before: cloneMatrix(state), roundKeyUsed: roundKeys[round] };
      state = addRoundKey(state, roundKeys[round]);
      stepLog.addRoundKey.after = cloneMatrix(state);

      stepLog.invMixColumns = { before: cloneMatrix(state) };
      state = mixColumns(state, true);
      stepLog.invMixColumns.after = cloneMatrix(state);

      steps.rounds.push(stepLog);
    }

    // Final round (ronde 0): InvShiftRows, InvSubBytes, AddRoundKey dgn RK0 (tanpa InvMixColumns)
    const finalLog = { round: 0 };
    finalLog.invShiftRows = { before: cloneMatrix(state) };
    state = shiftRows(state, true);
    finalLog.invShiftRows.after = cloneMatrix(state);

    finalLog.invSubBytes = { before: cloneMatrix(state) };
    state = subBytes(state, true);
    finalLog.invSubBytes.after = cloneMatrix(state);

    finalLog.addRoundKey = { before: cloneMatrix(state), roundKeyUsed: roundKeys[0] };
    state = addRoundKey(state, roundKeys[0]);
    finalLog.addRoundKey.after = cloneMatrix(state);
    steps.rounds.push(finalLog);

    steps.plaintext = matrixToHex(state);
    return { plaintextHex: matrixToHex(state), steps };
  }

  return {
    SBOX, INV_SBOX, RCON,
    hexToBytes, bytesToHex, textToBytes16,
    bytesToMatrix, matrixToBytes, matrixToHex, cloneMatrix,
    gmul, subBytes, shiftRows, mixColumns, addRoundKey,
    keyExpansion, encrypt, decrypt
  };
})();

// Ekspor untuk Node.js (berguna untuk automated testing)
if (typeof module !== "undefined" && module.exports) module.exports = AES;
// Pastikan tersedia sebagai global di browser walau dievaluasi dalam scope terpisah
if (typeof window !== "undefined") window.AES = AES;
