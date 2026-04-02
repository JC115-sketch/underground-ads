// static/js/pgp-client.js
// Requires openpgp v5

const PGP_CLIENT = (function () {

  const LS_PRIVKEY = "ua_private_key_armored";

  //  cache decrypted key (THIS FIXES YOUR ISSUE)
  let cachedDecryptedKey = null;

  // =========================
  // KEY GENERATION
  // =========================
  async function generateKeypair(username = "User", email = "user@example.local") {
    const userIDs = [{ name: username, email }];
    const privkeyObj = await openpgp.generateKey({
      type: "ecc",
      curve: "curve25519",
      userIDs,
    });

    return {
      privateArmored: privkeyObj.privateKey,
      publicArmored: privkeyObj.publicKey,
    };
  }

  function downloadPrivateKey(privArmored, filename = "privatekey.asc") {
    const blob = new Blob([privArmored], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  function savePrivateKeyToLocalStorage(privArmored) {
    localStorage.setItem(LS_PRIVKEY, privArmored);
  }

  function removePrivateKeyFromLocalStorage() {
    localStorage.removeItem(LS_PRIVKEY);
    cachedDecryptedKey = null; // reset cache too
  }

  function getPrivateKeyFromLocalStorage() {
    return localStorage.getItem(LS_PRIVKEY);
  }

  // =========================
  //  KEY UNLOCK (CORE FIX)
  // =========================
  async function getDecryptedPrivateKey(privArmored) {
    if (cachedDecryptedKey) return cachedDecryptedKey;

    if (!privArmored) {
      throw new Error("No private key available");
    }

    const passphrase = prompt("Enter your PGP passphrase:");

    const privateKey = await openpgp.readPrivateKey({
      armoredKey: privArmored
    });

    cachedDecryptedKey = await openpgp.decryptKey({
      privateKey,
      passphrase
    });

    return cachedDecryptedKey;
  }

  // =========================
  // ENCRYPTION
  // =========================
  async function encryptForPublicKey(plainText, recipientPubArmored) {
    const publicKey = await openpgp.readKey({ armoredKey: recipientPubArmored });
    const message = await openpgp.createMessage({ text: plainText });

    return await openpgp.encrypt({
      message,
      encryptionKeys: publicKey,
    });
  }

  // =========================
  //  DECRYPTION (FIXED)
  // =========================
  async function decryptWithPrivateArmored(armoredMessage, privArmored) {
    const decryptedKey = await getDecryptedPrivateKey(privArmored);

    const message = await openpgp.readMessage({
      armoredMessage
    });

    const { data: decrypted } = await openpgp.decrypt({
      message,
      decryptionKeys: decryptedKey
    });

    return decrypted;
  }

  // =========================
  // API CALLS
  // =========================
  async function uploadPublicKey(pubArmored) {
    if (!pubArmored || pubArmored.trim().length === 0) {
      throw new Error("No public key provided");
    }

    const body = "pubkey=" + encodeURIComponent(pubArmored);

    const resp = await fetch("/upload_pubkey", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body,
    });

    let text = await resp.text();
    try {
      return { ok: resp.ok, status: resp.status, body: JSON.parse(text) };
    } catch {
      return { ok: resp.ok, status: resp.status, body: text };
    }
  }

  async function sendEncryptedMessage(recipientId, armoredContent, adId = null) {
    const form = new URLSearchParams();
    form.append("recipient_id", String(recipientId));
    form.append("content", armoredContent);
    if (adId !== null) form.append("ad_id", String(adId));

    const resp = await fetch("/send_encrypted", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form.toString(),
    });

    if (!resp.ok) {
      const t = await resp.text();
      throw new Error("send_encrypted failed: " + resp.status + " " + t);
    }

    return resp.json();
  }

  async function fetchMessagesWith(otherId) {
    const resp = await fetch(`/fetch_messages?other_id=${encodeURIComponent(otherId)}`);

    if (!resp.ok) {
      const t = await resp.text();
      throw new Error("fetch_messages failed: " + resp.status + " " + t);
    }

    return resp.json();
  }

  // =========================
  //  MESSAGE DECRYPT LOOP
  // =========================
  async function decryptMessagesArray(msgRows, privArmored) {
    const out = [];

    for (const r of msgRows) {

      if (r.is_encrypted) {

        // Don't decrypt messages you sent
        if (r.sender_id === window.CURRENT_USER_ID) {
          out.push({
            ...r,
            decrypted: "[Encrypted message sent]",
            error: null
          });
          continue;
        }

        if (!privArmored) {
          out.push({
            ...r,
            decrypted: null,
            error: "No private key available"
          });
          continue;
        }

        if (!r.content.includes("BEGIN PGP MESSAGE")) {
          out.push({
            ...r,
            decrypted: null,
            error: "Malformed encrypted message"
          });
          continue;
        }

        try {
          const plain = await decryptWithPrivateArmored(r.content, privArmored);
          out.push({ ...r, decrypted: plain, error: null });
        } catch (e) {
          out.push({ ...r, decrypted: null, error: String(e) });
        }

      } else {
        out.push({
          ...r,
          decrypted: r.content,
          error: null
        });
      }
    }

    return out;
  }

  // =========================
  // UI HOOK
  // =========================
  document.addEventListener("DOMContentLoaded", function () {
    const uploadBtn = document.getElementById("uploadPubBtn");
    const pubInput = document.getElementById("pubkeyInput");

    if (uploadBtn && pubInput) {
      uploadBtn.addEventListener("click", async function () {
        try {
          const candidate = window._lastGeneratedPublicKey || pubInput.value.trim();

          if (!candidate) {
            alert("No public key found.");
            return;
          }

          uploadBtn.disabled = true;
          uploadBtn.innerText = "Uploading…";

          const result = await uploadPublicKey(candidate);

          if (result.ok) {
            alert("Public key uploaded successfully.");
          } else {
            alert("Upload failed.");
          }

        } catch (e) {
          alert("Upload failed: " + e.message);
        } finally {
          uploadBtn.disabled = false;
          uploadBtn.innerText = "Upload Public Key to Server";
        }
      });
    }
  });

  return {
    generateKeypair,
    downloadPrivateKey,
    savePrivateKeyToLocalStorage,
    removePrivateKeyFromLocalStorage,
    getPrivateKeyFromLocalStorage,
    uploadPublicKey,
    encryptForPublicKey,
    decryptWithPrivateArmored,
    sendEncryptedMessage,
    fetchMessagesWith,
    decryptMessagesArray,
  };

})();