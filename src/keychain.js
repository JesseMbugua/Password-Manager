"use strict";

const {
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
} = require("./crypto-utils");

const { subtle } = require("crypto").webcrypto;

// ==================== KEYCHAIN CLASS ====================

class Keychain {
  constructor(masterKey, hmacKey, aesKey, salt) {
    this.masterKey = masterKey;
    this.hmacKey = hmacKey;
    this.aesKey = aesKey;
    this.salt = salt;
    this.kvs = {};
  }

  static async init(password) {
    const salt = getRandomBytes(16);
    const masterKey = await deriveMasterKey(password, salt);
    const hmacKey = await deriveHmacKey(masterKey);
    const aesKey = await deriveAesKey(masterKey);
    return new Keychain(masterKey, hmacKey, aesKey, salt);
  }

  // serialize current state to JSON + hash
  async dump() {
    // include a small verification tag signed with the HMAC key so loaders can
    // verify the correct password without having to decrypt entries.
    const verifySigBuf = await subtle.sign(
      "HMAC",
      this.hmacKey,
      stringToBuffer("verify")
    );
    const verify = encodeBuffer(verifySigBuf);

    const reprObj = {
      salt: encodeBuffer(this.salt), // Base64
      kvs: this.kvs,                 // encrypted entries
      verify: verify                 // verification tag
    };

    const json = JSON.stringify(reprObj);

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

    // Rollback detection (trustedHash optional)
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

    // Verify the verification tag (if present). If it doesn't match, the
    // password is wrong (or the file was tampered with).
    if (data.verify !== undefined) {
      const expectedSigBuf = await subtle.sign(
        "HMAC",
        hmacKey,
        stringToBuffer("verify")
      );
      const expectedSig = encodeBuffer(expectedSigBuf);

      if (expectedSig !== data.verify) {
        throw "Incorrect password";
      }
    }

    // Rebuild instance
    const kc = new Keychain(masterKey, hmacKey, aesKey, saltBuf);
    kc.kvs = data.kvs;

    // As a final guard: if there are entries, attempt a decryption; if it
    // fails, the password is incorrect (this is defensive and should rarely
    // be hit because the verify tag already checked HMAC correctness).
    const domainKeys = Object.keys(kc.kvs);
    if (domainKeys.length > 0) {
      const firstEncrypted = kc.kvs[domainKeys[0]];
      try {
        await decryptValue(aesKey, firstEncrypted);
      } catch (e) {
        throw "Incorrect password";
      }
    }

    return kc;
  }



  async set(name, value) {
    const domainKey = await computeDomainKey(this.hmacKey, name);
    const encryptedValue = await encryptValue(this.aesKey, value);
    this.kvs[domainKey] = encryptedValue;
  }

  async get(name) {
    const domainKey = await computeDomainKey(this.hmacKey, name);
    const encryptedValue = this.kvs[domainKey];
    if (!encryptedValue) return null;
    return await decryptValue(this.aesKey, encryptedValue);
  }

  async remove(name) {
    const domainKey = await computeDomainKey(this.hmacKey, name);
    if (!(domainKey in this.kvs)) return false;
    delete this.kvs[domainKey];
    return true;
  }
}

module.exports = Keychain;
