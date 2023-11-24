let public_key;
let private_key;

let public_signing_key;
let private_signing_key;

const qs = (selector) => document.querySelector(selector);

async function generateRSAKeyPair() {
  // From what I can gather from online sources,
  // the in browser crypto module can not generate keys that can be used for both signing and encryption.
  // For this example we will just generate two key pairs, and use them for their recommended purpose.

  // Create Encryption/Decryption keypair
  const encryption_keypair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );

  // Create signing keypair
  const signing_keypair = await window.crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"]
  );

  // These keys will be used to encrypt data
  public_key = encryption_keypair.publicKey;
  private_key = encryption_keypair.privateKey;

  // These keys will be used to "sign" messages
  public_signing_key = signing_keypair.publicKey;
  private_signing_key = signing_keypair.privateKey;

  // Update displays
  qs("#pub-key-enc").innerText = await _exportKey(public_key, "spki");
  qs("#priv-key-enc").innerText = await _exportKey(private_key, "jwk");

  qs("#pub-key-sign").innerText = await _exportKey(public_signing_key, "spki");
  qs("#priv-key-sign").innerText = await _exportKey(private_signing_key, "jwk");
}
async function executeTests() {
  const user_string = document.querySelector("#my-secret-string").value;

  // Get our data with our generated keys and user-submitted text
  const encrypted_string = await encryptString(user_string);
  const decrypted_string = await decryptString(encrypted_string);
  const signed_message = await signMessage(user_string);
  const message_verified = await verifyMessage(user_string, signed_message);

  // Generate Results
  let results = `Message Signature Verified? ${message_verified}<br>`;

  qs("#encrypted-string").innerText = new Uint8Array(encrypted_string).toString();
  qs("#decrypted-string").innerText = decrypted_string;
  qs("#signature-string").innerText = new Uint8Array(signed_message).toString();
  qs("#results").innerHTML = results;
}

async function encryptString(string_d) {
  return await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, public_key, new TextEncoder().encode(string_d));
}
async function decryptString(string_d) {
  return new TextDecoder().decode(await window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, private_key, string_d));
}

async function signMessage(string_d) {
  return await window.crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, private_signing_key, new TextEncoder().encode(string_d));
}
async function verifyMessage(string_d, signed_message) {
  return await window.crypto.subtle.verify("RSASSA-PKCS1-v1_5", public_signing_key, signed_message, new TextEncoder().encode(string_d));
}

// This is just used to turn the data into string that can be read.
// Ordinarily you won't need this, as the keys won't need to be visible in the way this website wants them to be.
// (Hint, this is very bad! Do not do this!)
async function _exportKey(key, method) {
  const exported = await window.crypto.subtle.exportKey(method, key);
  if (exported.e) return JSON.stringify(exported, null, 2);
  return String.fromCharCode.apply(null, new Uint8Array(exported));
}
