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
  // Import password as a CryptoKey
  const passwordKey = await subtle.importKey(
    "raw",
    stringToBuffer(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits", "deriveKey"]
  );

  // Derive master key using PBKDF2 with 100,000 iterations
  const masterKey = await subtle.deriveKey(
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

  return masterKey;
}

/**
 * Derives HMAC key from master key
 * k_HMAC = HMAC(k, "hmac")
 * @param {CryptoKey} masterKey - Master key
 * @returns {Promise<CryptoKey>} HMAC key for domain hashing
 */
async function deriveHmacKey(masterKey) {
  // Sign "hmac" with master key
  const hmacData = await subtle.sign("HMAC", masterKey, stringToBuffer("hmac"));

  // Import the result as a new HMAC key
  const hmacKey = await subtle.importKey(
    "raw",
    hmacData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  return hmacKey;
}

/**
 * Derives AES key from master key
 * k_AES = HMAC(k, "aes")
 * @param {CryptoKey} masterKey - Master key
 * @returns {Promise<CryptoKey>} AES-GCM key for encryption
 */
async function deriveAesKey(masterKey) {
  // Sign "aes" with master key
  const aesData = await subtle.sign("HMAC", masterKey, stringToBuffer("aes"));

  // Import the result as an AES-GCM key (first 256 bits)
  const aesKey = await subtle.importKey(
    "raw",
    aesData.slice(0, 32), // Use first 256 bits
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );

  return aesKey;
}

// ==================== ENCRYPTION / DECRYPTION ====================

/**
 * Encrypts a value using AES-GCM
 * @param {CryptoKey} aesKey - AES-GCM key
 * @param {string} plaintext - Plaintext to encrypt
 * @returns {Promise<string>} Base64 encoded ciphertext with IV
 */
async function encryptValue(aesKey, plaintext) {
  // Pad plaintext to fixed length (64 chars) to prevent length leakage
  const paddedPlaintext = plaintext.padEnd(64, "\0");

  // Generate random 96-bit IV (recommended for AES-GCM)
  const iv = getRandomBytes(12);

  // Encrypt using AES-GCM
  const ciphertext = await subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
      tagLength: 128, // 128-bit authentication tag
    },
    aesKey,
    stringToBuffer(paddedPlaintext)
  );

  // Concatenate IV + ciphertext for storage
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), iv.length);

  return encodeBuffer(combined);
}

/**
 * Decrypts a value using AES-GCM
 * @param {CryptoKey} aesKey - AES-GCM key
 * @param {string} encryptedData - Base64 encoded IV + ciphertext
 * @returns {Promise<string>} Decrypted plaintext (trimmed)
 */
async function decryptValue(aesKey, encryptedData) {
  // Decode from Base64
  const combined = decodeBuffer(encryptedData);

  // Extract IV (first 12 bytes) and ciphertext
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);

  try {
    // Decrypt using AES-GCM
    const decrypted = await subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv,
        tagLength: 128,
      },
      aesKey,
      ciphertext
    );

    // Convert to string and remove padding
    const plaintext = bufferToString(decrypted);
    return plaintext.replace(/\0+$/, ""); // Remove null padding
  } catch (e) {
    throw "Decryption failed: invalid ciphertext or key";
  }
}

/**
 * Computes HMAC hash of domain name for key-value lookup
 * @param {CryptoKey} hmacKey - HMAC key
 * @param {string} domain - Domain name
 * @returns {Promise<string>} Base64 encoded HMAC
 */
async function computeDomainKey(hmacKey, domain) {
  const signature = await subtle.sign("HMAC", hmacKey, stringToBuffer(domain));
  return encodeBuffer(signature);
}

// ==================== KEYCHAIN CLASS ====================

// Data storage
class Keychain {
  constructor(masterKey, hmacKey, aesKey, salt) {
    this.masterKey = masterKey;
    this.hmacKey = hmacKey;
    this.aesKey = aesKey;
    this.salt = salt; // raw buffer
    this.kvs = {}; // required field for autograder
  }

  static async init(password) {
    // Jesse's functions are to be expected
    const salt = getRandomBytes(16);

    const masterKey = await deriveMasterKey(password, salt);
    const hmacKey = await deriveHmacKey(masterKey);
    const aesKey = await deriveAesKey(masterKey);

    return new Keychain(masterKey, hmacKey, aesKey, salt);
  }

  // serialize current state to JSON + hash
  async dump() {
    const repr = {
      salt: encodeBuffer(this.salt), // Base64
      kvs: this.kvs, // encrypted entries
    };

    const json = JSON.stringify(repr);

    // SHA-256 over exact JSON text
    const hashBuf = await subtle.digest("SHA-256", stringToBuffer(json));
    const hash = encodeBuffer(hashBuf);

    return [json, hash];
  }

  // parse from JSON + verify hash
  static async load(password, repr, trustedHash) {
    let data;
    try {
      data = JSON.parse(repr);
    } catch (e) {
      throw "Invalid JSON representation";
    }

    if (!data.salt || !data.kvs) throw "Missing salt or kvs";

    // Rollback detection
    if (trustedHash !== undefined) {
      const computedHashBuf = await subtle.digest(
        "SHA-256",
        stringToBuffer(repr)
      );
      const computedHash = encodeBuffer(computedHashBuf);

      if (computedHash !== trustedHash)
        throw "Rollback detected: hash mismatch";
    }

    // Recreate keys
    const saltBuf = decodeBuffer(data.salt);

    const masterKey = await deriveMasterKey(password, saltBuf);
    const hmacKey = await deriveHmacKey(masterKey);
    const aesKey = await deriveAesKey(masterKey);

    // Rebuild instance
    const kc = new Keychain(masterKey, hmacKey, aesKey, saltBuf);
    kc.kvs = data.kvs;

    return kc;
  }

  /**
   * Sets/updates a password for a domain
   * @param {string} name - Domain name
   * @param {string} value - Password to store
   */
  async set(name, value) {
    const domainKey = await computeDomainKey(this.hmacKey, name);
    const encryptedValue = await encryptValue(this.aesKey, value);
    this.kvs[domainKey] = encryptedValue;
  }

  /**
   * Gets a password for a domain
   * @param {string} name - Domain name
   * @returns {Promise<string|null>} Decrypted password or null if not found
   */
  async get(name) {
    const domainKey = await computeDomainKey(this.hmacKey, name);
    const encryptedValue = this.kvs[domainKey];

    if (!encryptedValue) {
      return null;
    }

    return await decryptValue(this.aesKey, encryptedValue);
  }

  /**
   * Removes a password entry for a domain
   * @param {string} name - Domain name
   * @returns {Promise<boolean>} True if removed, false if not found
   */
  async remove(name) {
    const domainKey = await computeDomainKey(this.hmacKey, name);

    if (!(domainKey in this.kvs)) {
      return false;
    }

    delete this.kvs[domainKey];
    return true;
  }
}

// Export for autograder
module.exports = Keychain;
