"use strict";

// Import SubtleCrypto for Node.js
const { subtle } = require("crypto").webcrypto;

// ==================== HELPER UTILITIES ====================

/**
 * Generates cryptographically secure random bytes
 * @param {number} length - Number of bytes to generate
 * @returns {Uint8Array} Random bytes
 */
function getRandomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Encodes a buffer to Base64 string
 * @param {ArrayBuffer | Uint8Array} buffer - Buffer to encode
 * @returns {string} Base64 encoded string
 */
function encodeBuffer(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Decodes a Base64 string to buffer
 * @param {string} base64 - Base64 encoded string
 * @returns {Uint8Array} Decoded buffer
 */
function decodeBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Converts a string to ArrayBuffer
 * @param {string} str - String to convert
 * @returns {Uint8Array} Buffer representation
 */
function stringToBuffer(str) {
  return new TextEncoder().encode(str);
}

/**
 * Converts an ArrayBuffer to string
 * @param {ArrayBuffer} buffer - Buffer to convert
 * @returns {string} String representation
 */
function bufferToString(buffer) {
  return new TextDecoder().decode(buffer);
}

// ==================== KEY DERIVATION ====================

/**
 * Derives a master key from password using PBKDF2
 * @param {string} password - Master password
 * @param {Uint8Array} salt - 128-bit salt
 * @returns {Promise<CryptoKey>} Derived master key
 */
async function deriveMasterKey(password, salt) {
  const passwordKey = await subtle.importKey(
    "raw",
    stringToBuffer(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits", "deriveKey"]
  );

  return await subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    passwordKey,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    true,
    ["sign"]
  );
}

/**
 * Derives HMAC key from master key
 * k_HMAC = HMAC(k, "hmac")
 */
async function deriveHmacKey(masterKey) {
  const hmacData = await subtle.sign("HMAC", masterKey, stringToBuffer("hmac"));
  return await subtle.importKey(
    "raw",
    hmacData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
}

/**
 * Derives AES key from master key
 * k_AES = HMAC(k, "aes")
 */
async function deriveAesKey(masterKey) {
  const aesData = await subtle.sign("HMAC", masterKey, stringToBuffer("aes"));
  return await subtle.importKey(
    "raw",
    aesData.slice(0, 32),
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}

// ==================== ENCRYPTION / DECRYPTION ====================

/**
 * Encrypts a value using AES-GCM
 */
async function encryptValue(aesKey, plaintext) {
  const paddedPlaintext = plaintext.padEnd(64, "\0");
  const iv = getRandomBytes(12);

  const ciphertext = await subtle.encrypt(
    { name: "AES-GCM", iv: iv, tagLength: 128 },
    aesKey,
    stringToBuffer(paddedPlaintext)
  );

  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), iv.length);

  return encodeBuffer(combined);
}

/**
 * Decrypts a value using AES-GCM
 */
async function decryptValue(aesKey, encryptedData) {
  const combined = decodeBuffer(encryptedData);
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);

  const decrypted = await subtle.decrypt(
    { name: "AES-GCM", iv: iv, tagLength: 128 },
    aesKey,
    ciphertext
  );

  return bufferToString(decrypted).replace(/\0+$/, "");
}

/**
 * Computes HMAC hash of domain name
 */
async function computeDomainKey(hmacKey, domain) {
  const signature = await subtle.sign("HMAC", hmacKey, stringToBuffer(domain));
  return encodeBuffer(signature);
}

module.exports = {
  getRandomBytes,
  encodeBuffer,
  decodeBuffer,
  stringToBuffer,
  bufferToString,
  deriveMasterKey,
  deriveHmacKey,
  deriveAesKey,
  encryptValue,
  decryptValue,
  computeDomainKey
};
