/* =============================================================================
   ui.js — mengikat AES-core ke antarmuka & merender semua State Matrix
   ========================================================================= */
(function () {
  "use strict";

  // ------------------------------------------------------------------ state
  let ptFormat = "text";   // 'text' | 'hex'
  let mode = "encrypt";    // 'encrypt' | 'decrypt'

  // ------------------------------------------------------------------ DOM refs
  const $ = (sel) => document.querySelector(sel);
  const ptFormatToggle = $("#ptFormatToggle");
  const plaintextInput = $("#plaintextInput");
  const ptLabel = $("#ptLabel");
  const ptHint = $("#ptHint");
  const keyInput = $("#keyInput");
  const keyHint = $("#keyHint");
  const modeToggle = $("#modeToggle");
  const cipherInputWrap = $("#cipherInputWrap");
  const ciphertextInput = $("#ciphertextInput");
  const ctHint = $("#ctHint");
  const showDetailToggle = $("#showDetailToggle");
  const errorBox = $("#errorBox");
  const runBtn = $("#runBtn");
  const runBtnLabel = $("#runBtnLabel");
  const resetBtn = $("#resetBtn");
  const outputDisplay = $("#outputDisplay");
  const copyBtn = $("#copyBtn");
  const detailWrap = $("#detailWrap");
  const detailContent = $("#detailContent");
  const sideNavList = $("#sideNavList");

  // ------------------------------------------------------------------ helpers: validation / formatting
  function isHex(str) { return /^[0-9a-fA-F]*$/.test(str); }

  function updateHints() {
    const ptLen = plaintextInput.value.length;
    if (ptFormat === "text") {
      ptHint.textContent = `${ptLen} / 16 karakter · akan di-padding dengan 0x00 bila kurang dari 16 byte`;
    } else {
      ptHint.textContent = `${ptLen} / 32 karakter hex (16 byte)`;
    }
    keyHint.textContent = `${keyInput.value.length} / 32 karakter hex`;
    if (mode === "decrypt") ctHint.textContent = `${ciphertextInput.value.length} / 32 karakter hex`;
  }

  function showError(msg) {
    errorBox.hidden = false;
    errorBox.textContent = msg;
  }
  function clearError() {
    errorBox.hidden = true;
    errorBox.textContent = "";
  }

  // ------------------------------------------------------------------ toggles
  ptFormatToggle.addEventListener("click", (e) => {
    const btn = e.target.closest(".seg-btn");
    if (!btn) return;
    ptFormatToggle.querySelectorAll(".seg-btn").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    ptFormat = btn.dataset.fmt;
    if (ptFormat === "text") {
      plaintextInput.maxLength = 16;
      plaintextInput.placeholder = "Contoh: HELLO CRYPTOGRAPHY";
      ptLabel.textContent = "Plaintext";
    } else {
      plaintextInput.maxLength = 32;
      plaintextInput.placeholder = "3243f6a8885a308d313198a2e0370734";
      ptLabel.textContent = "Plaintext (hex)";
    }
    plaintextInput.value = "";
    updateHints();
  });

  modeToggle.addEventListener("click", (e) => {
    const btn = e.target.closest(".seg-btn");
    if (!btn) return;
    modeToggle.querySelectorAll(".seg-btn").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    mode = btn.dataset.mode;
    cipherInputWrap.style.display = mode === "decrypt" ? "block" : "none";
    runBtnLabel.textContent = mode === "decrypt" ? "JALANKAN DEKRIPSI" : "JALANKAN ENKRIPSI";
    updateHints();
  });

  [plaintextInput, keyInput, ciphertextInput].forEach((el) => el.addEventListener("input", () => {
    el.classList.remove("invalid");
    updateHints();
  }));

  resetBtn.addEventListener("click", () => {
    plaintextInput.value = "";
    keyInput.value = "";
    ciphertextInput.value = "";
    clearError();
    outputDisplay.innerHTML = '<span class="output-placeholder">Hasil akan muncul di sini setelah dijalankan&hellip;</span>';
    copyBtn.style.display = "none";
    detailWrap.style.display = "none";
    detailContent.innerHTML = "";
    sideNavList.innerHTML = "";
    updateHints();
  });

  copyBtn.addEventListener("click", () => {
    const hex = outputDisplay.dataset.hex || "";
    if (!hex) return;
    navigator.clipboard.writeText(hex).then(() => {
      copyBtn.textContent = "TERSALIN ✓";
      setTimeout(() => (copyBtn.textContent = "SALIN HASIL"), 1500);
    });
  });

  // ------------------------------------------------------------------ rendering: state matrix table
  function matrixTableHTML(matrix, { accent = "", diffAgainst = null } = {}) {
    let html = `<table class="state-matrix ${accent}">`;
    for (let r = 0; r < 4; r++) {
      html += "<tr>";
      for (let c = 0; c < 4; c++) {
        const v = matrix[r][c];
        const changed = diffAgainst && diffAgainst[r][c] !== v ? " changed" : "";
        html += `<td class="${changed.trim()}">${v.toString(16).toUpperCase().padStart(2, "0")}</td>`;
      }
      html += "</tr>";
    }
    html += "</table>";
    return html;
  }

  function matrixPairHTML(before, after, labelBefore, labelAfter, accent) {
    return `
      <div class="matrix-row-flex">
        <div class="matrix-unit">
          <div class="matrix-label">${labelBefore}</div>
          ${matrixTableHTML(before, { accent })}
        </div>
        <div class="matrix-arrow">&#8594;</div>
        <div class="matrix-unit">
          <div class="matrix-label">${labelAfter}</div>
          ${matrixTableHTML(after, { accent, diffAgainst: before })}
        </div>
      </div>`;
  }

  function opBlock({ dotClass, title, bodyHTML }) {
    return `
      <div class="op-block">
        <div class="op-block-title"><span class="dot ${dotClass}"></span>${title}</div>
        ${bodyHTML}
      </div>`;
  }

  // ------------------------------------------------------------------ Key Expansion section
  function buildKeyExpansionSection(ke) {
    const rkCards = ke.roundKeys.map((rk, i) => `
      <div class="roundkey-card">
        <div class="rk-label">RK${i}</div>
        ${matrixTableHTML(rk, { accent: "accent-key" })}
      </div>`).join("");

    const wordRows = ke.words.map((w, i) => {
      const hex = w.map(b => b.toString(16).toUpperCase().padStart(2, "0")).join(" ");
      const hasG = ke.gLog[i];
      const rowClass = hasG ? "g-row" : "";
      const toggleBtn = hasG ? `<button class="g-toggle" data-gidx="${i}">lihat fungsi g()</button>` : "—";
      let rows = `<tr class="${rowClass}"><td>W[${i}]</td><td>${hex}</td><td>${toggleBtn}</td></tr>`;
      if (hasG) {
        const g = ke.gLog[i];
        const fmt = (arr) => arr.map(b => b.toString(16).toUpperCase().padStart(2, "0")).join(" ");
        rows += `
          <tr class="g-detail-row" id="gdetail-${i}" style="display:none;">
            <td colspan="3">
              <div class="g-detail-grid">
                <div class="g-step"><div class="g-step-label">W[${i-1}]</div><div class="g-step-val">${fmt(g.before)}</div></div>
                <div class="g-step"><div class="g-step-label">RotWord</div><div class="g-step-val">${fmt(g.afterRotWord)}</div></div>
                <div class="g-step"><div class="g-step-label">SubWord</div><div class="g-step-val">${fmt(g.afterSubWord)}</div></div>
                <div class="g-step"><div class="g-step-label">XOR Rcon[${i/4}]</div><div class="g-step-val">${fmt(g.rcon)}</div></div>
                <div class="g-step"><div class="g-step-label">Hasil g(W[${i-1}])</div><div class="g-step-val">${fmt(g.afterXorRcon)}</div></div>
              </div>
            </td>
          </tr>`;
      }
      return rows;
    }).join("");

    return `
      <details class="op-section" id="sec-keyexpansion" open>
        <summary><span><span class="section-tag tag-key">KEY EXPANSION</span>Pembangkitan Round Key (W0 &ndash; W43)</span><span class="chev">&#9656;</span></summary>
        <div class="op-body">
          ${opBlock({ dotClass: "dot-key", title: "State Awal Kunci (Cipher Key)", bodyHTML: matrixTableHTML(ke.initialKeyMatrix, { accent: "accent-key" }) })}

          <div class="op-block">
            <div class="op-block-title"><span class="dot dot-key"></span>Key Schedule — Word W[0] s/d W[43]</div>
            <p class="field-hint">Setiap word yang indeksnya kelipatan 4 melalui fungsi g (RotWord &rarr; SubWord &rarr; XOR Rcon) sebelum di-XOR dengan W[i-4].</p>
            <div class="words-table-wrap">
              <table class="words-table">
                <thead><tr><th>Index</th><th>Nilai (hex)</th><th>Fungsi g</th></tr></thead>
                <tbody>${wordRows}</tbody>
              </table>
            </div>
          </div>

          <div class="op-block">
            <div class="op-block-title"><span class="dot dot-key"></span>Round Key RK0 &ndash; RK10</div>
            <div class="roundkey-grid">${rkCards}</div>
          </div>
        </div>
      </details>`;
  }

  // ------------------------------------------------------------------ Initial round (shared)
  function buildInitialRoundSection(initRound, headingText, idSuffix) {
    return `
      <details class="op-section" id="sec-initial-${idSuffix}" open>
        <summary><span><span class="section-tag tag-add">INITIAL</span>${headingText}</span><span class="chev">&#9656;</span></summary>
        <div class="op-body">
          ${opBlock({
            dotClass: "dot-add",
            title: `AddRoundKey dengan ${idSuffix === 'enc' ? 'RK0' : 'RK10'}`,
            bodyHTML: `
              <div class="matrix-row-flex">
                <div class="matrix-unit"><div class="matrix-label">State Masuk</div>${matrixTableHTML(initRound.stateIn)}</div>
                <div class="matrix-arrow">XOR</div>
                <div class="matrix-unit"><div class="matrix-label">Round Key</div>${matrixTableHTML(initRound.roundKeyUsed, { accent: "accent-key" })}</div>
                <div class="matrix-arrow">&#8594;</div>
                <div class="matrix-unit"><div class="matrix-label">State Keluar</div>${matrixTableHTML(initRound.stateOut, { accent: "accent-key", diffAgainst: initRound.stateIn })}</div>
              </div>`
          })}
        </div>
      </details>`;
  }

  // ------------------------------------------------------------------ Encryption round section
  function buildEncryptRoundSection(r) {
    const isFinal = r.round === 10;
    let body = "";
    body += opBlock({ dotClass: "dot-sub", title: "SubBytes (substitusi S-Box)", bodyHTML: matrixPairHTML(r.subBytes.before, r.subBytes.after, "Sebelum", "Sesudah", "accent-sub") });
    body += opBlock({ dotClass: "dot-shift", title: "ShiftRows (pergeseran baris)", bodyHTML: matrixPairHTML(r.shiftRows.before, r.shiftRows.after, "Sebelum", "Sesudah", "accent-shift") });
    if (!isFinal) {
      body += opBlock({ dotClass: "dot-mix", title: "MixColumns (perkalian matriks GF(2⁸))", bodyHTML: matrixPairHTML(r.mixColumns.before, r.mixColumns.after, "Sebelum", "Sesudah", "accent-mix") });
    }
    body += opBlock({
      dotClass: "dot-add",
      title: `AddRoundKey dengan RK${r.round}`,
      bodyHTML: `
        <div class="matrix-row-flex">
          <div class="matrix-unit"><div class="matrix-label">Sebelum</div>${matrixTableHTML(r.addRoundKey.before)}</div>
          <div class="matrix-arrow">XOR</div>
          <div class="matrix-unit"><div class="matrix-label">RK${r.round}</div>${matrixTableHTML(r.addRoundKey.roundKeyUsed, { accent: "accent-key" })}</div>
          <div class="matrix-arrow">&#8594;</div>
          <div class="matrix-unit"><div class="matrix-label">Sesudah</div>${matrixTableHTML(r.addRoundKey.after, { accent: "accent-key", diffAgainst: r.addRoundKey.before })}</div>
        </div>`
    });

    const tag = isFinal ? `<span class="section-tag tag-add">FINAL</span>` : `<span class="section-tag tag-sub">ROUND</span>`;
    const heading = isFinal ? "Round 10 — Final Round (tanpa MixColumns)" : `Round ${r.round}`;
    return `
      <details class="op-section" id="sec-round-enc-${r.round}">
        <summary><span>${tag}${heading}</span><span class="chev">&#9656;</span></summary>
        <div class="op-body">${body}</div>
      </details>`;
  }

  // ------------------------------------------------------------------ Decryption round section
  function buildDecryptRoundSection(r) {
    const isFinal = r.round === 0;
    let body = "";
    body += opBlock({ dotClass: "dot-shift", title: "InvShiftRows", bodyHTML: matrixPairHTML(r.invShiftRows.before, r.invShiftRows.after, "Sebelum", "Sesudah", "accent-shift") });
    body += opBlock({ dotClass: "dot-sub", title: "InvSubBytes (Inverse S-Box)", bodyHTML: matrixPairHTML(r.invSubBytes.before, r.invSubBytes.after, "Sebelum", "Sesudah", "accent-sub") });
    body += opBlock({
      dotClass: "dot-add",
      title: `AddRoundKey dengan RK${r.round}`,
      bodyHTML: `
        <div class="matrix-row-flex">
          <div class="matrix-unit"><div class="matrix-label">Sebelum</div>${matrixTableHTML(r.addRoundKey.before)}</div>
          <div class="matrix-arrow">XOR</div>
          <div class="matrix-unit"><div class="matrix-label">RK${r.round}</div>${matrixTableHTML(r.addRoundKey.roundKeyUsed, { accent: "accent-key" })}</div>
          <div class="matrix-arrow">&#8594;</div>
          <div class="matrix-unit"><div class="matrix-label">Sesudah</div>${matrixTableHTML(r.addRoundKey.after, { accent: "accent-key", diffAgainst: r.addRoundKey.before })}</div>
        </div>`
    });
    if (!isFinal) {
      body += opBlock({ dotClass: "dot-mix", title: "InvMixColumns", bodyHTML: matrixPairHTML(r.invMixColumns.before, r.invMixColumns.after, "Sebelum", "Sesudah", "accent-mix") });
    }

    const tag = isFinal ? `<span class="section-tag tag-add">FINAL</span>` : `<span class="section-tag tag-sub">ROUND</span>`;
    const heading = isFinal ? "Round 0 — Final Round (tanpa InvMixColumns)" : `Round ${r.round}`;
    return `
      <details class="op-section" id="sec-round-dec-${r.round}">
        <summary><span>${tag}${heading}</span><span class="chev">&#9656;</span></summary>
        <div class="op-body">${body}</div>
      </details>`;
  }

  // ------------------------------------------------------------------ output banner
  function buildOutputBanner(hex, label) {
    return `
      <div class="final-output-banner">
        <span class="fob-label">${label}</span>
        <span class="fob-hex">${hex}</span>
      </div>`;
  }

  // ------------------------------------------------------------------ side nav
  function buildSideNav(items) {
    sideNavList.innerHTML = items.map(it => `<li><a href="#${it.id}" data-target="${it.id}">${it.label}</a></li>`).join("");
    sideNavList.querySelectorAll("a").forEach(a => {
      a.addEventListener("click", (e) => {
        e.preventDefault();
        const target = document.getElementById(a.dataset.target);
        if (target) {
          target.open = true;
          target.scrollIntoView({ behavior: "smooth", block: "start" });
          sideNavList.querySelectorAll("a").forEach(x => x.classList.remove("active"));
          a.classList.add("active");
        }
      });
    });
  }

  // ------------------------------------------------------------------ g-toggle delegation
  detailContent.addEventListener("click", (e) => {
    const btn = e.target.closest(".g-toggle");
    if (!btn) return;
    const row = document.getElementById(`gdetail-${btn.dataset.gidx}`);
    if (row) row.style.display = row.style.display === "none" ? "table-row" : "none";
  });

  // ------------------------------------------------------------------ main run
  runBtn.addEventListener("click", () => {
    clearError();

    // --- validasi kunci ---
    const keyRaw = keyInput.value.trim();
    if (keyRaw.length !== 32 || !isHex(keyRaw)) {
      keyInput.classList.add("invalid");
      showError("Kunci harus berupa 32 karakter heksadesimal (16 byte / AES-128).");
      return;
    }
    const keyBytes = AES.hexToBytes(keyRaw);

    let resultObj, sideNavItems = [], sectionsHTML = "";

    if (mode === "encrypt") {
      // --- validasi plaintext ---
      let ptBytes;
      const ptRaw = plaintextInput.value;
      if (ptFormat === "text") {
        if (ptRaw.length === 0) { plaintextInput.classList.add("invalid"); showError("Plaintext tidak boleh kosong."); return; }
        if (ptRaw.length > 16) { plaintextInput.classList.add("invalid"); showError("Plaintext teks maksimal 16 karakter."); return; }
        ptBytes = AES.textToBytes16(ptRaw);
      } else {
        if (ptRaw.length !== 32 || !isHex(ptRaw)) { plaintextInput.classList.add("invalid"); showError("Plaintext hex harus 32 karakter heksadesimal (16 byte)."); return; }
        ptBytes = AES.hexToBytes(ptRaw);
      }

      resultObj = AES.encrypt(ptBytes, keyBytes);
      outputDisplay.innerHTML = `<span class="output-hex">${resultObj.ciphertextHex}</span>`;
      outputDisplay.dataset.hex = resultObj.ciphertextHex;
      copyBtn.style.display = "inline-block";

      sectionsHTML += buildKeyExpansionSection(resultObj.steps.keyExpansion);
      sideNavItems.push({ id: "sec-keyexpansion", label: "Key Expansion" });

      sectionsHTML += buildInitialRoundSection(resultObj.steps.initialRound, "Initial Round — AddRoundKey dengan RK0", "enc");
      sideNavItems.push({ id: "sec-initial-enc", label: "Initial Round" });

      resultObj.steps.rounds.forEach((r) => {
        sectionsHTML += buildEncryptRoundSection(r);
        sideNavItems.push({ id: `sec-round-enc-${r.round}`, label: r.round === 10 ? "Round 10 (Final)" : `Round ${r.round}` });
      });

      sectionsHTML += buildOutputBanner(resultObj.ciphertextHex, "CIPHERTEXT (hasil akhir)");

    } else {
      // --- validasi ciphertext ---
      const ctRaw = ciphertextInput.value.trim();
      if (ctRaw.length !== 32 || !isHex(ctRaw)) { ciphertextInput.classList.add("invalid"); showError("Ciphertext harus 32 karakter heksadesimal (16 byte)."); return; }
      const ctBytes = AES.hexToBytes(ctRaw);

      resultObj = AES.decrypt(ctBytes, keyBytes);
      const hexOut = resultObj.plaintextHex;
      const asText = AES.hexToBytes(hexOut).map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : "·").join("");
      outputDisplay.innerHTML = `<span class="output-hex">${hexOut}</span> <span style="color:var(--muted); font-size:13px; margin-left:12px;">("${asText}")</span>`;
      outputDisplay.dataset.hex = hexOut;
      copyBtn.style.display = "inline-block";

      sectionsHTML += buildKeyExpansionSection(resultObj.steps.keyExpansion);
      sideNavItems.push({ id: "sec-keyexpansion", label: "Key Expansion" });

      sectionsHTML += buildInitialRoundSection(resultObj.steps.initialRound, "Initial Step — AddRoundKey dengan RK10", "dec");
      sideNavItems.push({ id: "sec-initial-dec", label: "AddRoundKey RK10" });

      resultObj.steps.rounds.forEach((r) => {
        sectionsHTML += buildDecryptRoundSection(r);
        sideNavItems.push({ id: `sec-round-dec-${r.round}`, label: r.round === 0 ? "Round 0 (Final)" : `Round ${r.round}` });
      });

      sectionsHTML += buildOutputBanner(hexOut, "PLAINTEXT (hasil akhir)");
    }

    if (showDetailToggle.checked) {
      detailContent.innerHTML = sectionsHTML;
      buildSideNav(sideNavItems);
      detailWrap.style.display = "grid";
    } else {
      detailWrap.style.display = "none";
      detailContent.innerHTML = "";
    }
  });

  updateHints();
})();
