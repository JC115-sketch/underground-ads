// static/js/pgp-client.js
// Requires openpgp v5. Use the CDN script tag in your HTML:
// <script src="https://unpkg.com/openpgp@5/dist/openpgp.min.js"></script>

const PGP_CLIENT = (function () {
    // key in localStorage where private key is optionally stored
    const LS_PRIVKEY = "ua_private_key_armored";

    // helper: sleep for debugging if needed
    function sleep(ms) {
        return new Promise((res) => setTimeout(res, ms));
    }

    // Generate an ECC keypair (curve25519 for encryption)
    async function generateKeypair(username = "User", email = "user@example.local") {
        const userIDs = [{ name: username, email }];
        const privkeyObj = await openpgp.generateKey({
            type: "ecc",
            curve: "curve25519",
            userIDs,
        });

        // openpgp.generateKey returns { privateKey, publicKey }
        return {
            privateArmored: privkeyObj.privateKey,
            publicArmored: privkeyObj.publicKey,
        };
    }

    // Prompt user to download the private key as a file
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

    // Save private key in localStorage (optional, not recommended for high-risk sites)
    function savePrivateKeyToLocalStorage(privArmored) {
        localStorage.setItem(LS_PRIVKEY, privArmored);
    }

    // Remove private key from localStorage
    function removePrivateKeyFromLocalStorage() {
        localStorage.removeItem(LS_PRIVKEY);
    }

    // Get private key from localStorage (returns armored string or null)
    function getPrivateKeyFromLocalStorage() {
        return localStorage.getItem(LS_PRIVKEY);
    }

    // Upload public key to the server (/upload_pubkey)
    // Accepts either form POST or JSON; we use JSON here.
    async function uploadPublicKey(pubArmored) {
        const resp = await fetch("/upload_pubkey", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ pubkey: pubArmored }),
        });
        if (!resp.ok) {
            const text = await resp.text();
            throw new Error(`Upload failed: ${resp.status} ${text}`);
        }
        return resp.json();
    }

    // Encrypt a plaintext string using recipient public key (armored)
    async function encryptForPublicKey(plainText, recipientPubArmored) {
        const publicKey = await openpgp.readKey({ armoredKey: recipientPubArmored });
        const message = await openpgp.createMessage({ text: plainText });
        const encryptedArmored = await openpgp.encrypt({
            message,
            encryptionKeys: publicKey,
        });
        return encryptedArmored; // armored PGP message (string)
    }

    // Decrypt armored PGP message using an armored private key (unprotected)
    async function decryptWithPrivateArmored(armoredMessage, privArmored) {
        if (!privArmored) {
            throw new Error("No private key available to decrypt with.");
        }
        const privateKey = await openpgp.readPrivateKey({ armoredKey: privArmored });
        const message = await openpgp.readMessage({ armoredMessage });
        const { data: decrypted } = await openpgp.decrypt({
            message,
            decryptionKeys: privateKey,
        });
        return decrypted;
    }

    // Send encrypted message to server (/send_encrypted)
    // Accepts recipient_id (numeric), ad_id optional (or null), and armoredContent (string)
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

    // Fetch messages between current user and other_id from /fetch_messages?other_id=...
    async function fetchMessagesWith(otherId) {
        const resp = await fetch(`/fetch_messages?other_id=${encodeURIComponent(otherId)}`);
        if (!resp.ok) {
            const t = await resp.text();
            throw new Error("fetch_messages failed: " + resp.status + " " + t);
        }
        return resp.json(); // array of {id, content, is_encrypted, sender_id, sender_name, created_at}
    }

    // Convenience: try to decrypt many messages; returns array of objects with decrypted text (or error)
    async function decryptMessagesArray(msgRows, privArmored) {
        const out = [];
        for (const r of msgRows) {
            if (r.is_encrypted && privArmored) {
                try {
                    const plain = await decryptWithPrivateArmored(r.content, privArmored);
                    out.push({ ...r, decrypted: plain, error: null });
                } catch (e) {
                    out.push({ ...r, decrypted: null, error: String(e) });
                }
            } else if (r.is_encrypted) {
                out.push({ ...r, decrypted: null, error: "No private key available" });
            } else {
                // not encrypted
                out.push({ ...r, decrypted: r.content, error: null });
            }
        }
        return out;
    }

    // Public API
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
