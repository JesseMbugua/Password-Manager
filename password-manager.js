"use strict";

const { subtle } = require("crypto").webcrypto;

// ==================== HELPER UTILITIES ====================

function getRandomBytes(length) {
    return crypto.getRandomValues(new Uint8Array(length));
}

function encodeBuffer(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function decodeBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

function stringToBuffer(str) {
    return new TextEncoder().encode(str);
}

function bufferToString(buffer) {
    return new TextDecoder().decode(buffer);
}

// ==================== KEY DERIVATION ====================

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

async function encryptValue(aesKey, plaintext) {
    const padded = plaintext.padEnd(64, "\0");
    const iv = getRandomBytes(12);

    const ciphertext = await subtle.encrypt(
        { name: "AES-GCM", iv: iv, tagLength: 128 },
        aesKey,
        stringToBuffer(padded)
    );

    const combined = new Uint8Array(iv.length + ciphertext.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertext), iv.length);

    return encodeBuffer(combined);
}

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

async function computeDomainKey(hmacKey, domain) {
    const signature = await subtle.sign("HMAC", hmacKey, stringToBuffer(domain));
    return encodeBuffer(signature);
}

// ==================== KEYCHAIN CLASS ====================

class Keychain {
    constructor(masterKey, hmacKey, aesKey, salt) {
        this.masterKey = masterKey;
        this.hmacKey = hmacKey;
        this.aesKey = aesKey;
        this.salt = salt;

        this.kvs = {};
        this.reverse = {};   
    }

    static async init(password) {
        const salt = getRandomBytes(16);
        const masterKey = await deriveMasterKey(password, salt);
        const hmacKey = await deriveHmacKey(masterKey);
        const aesKey = await deriveAesKey(masterKey);
        return new Keychain(masterKey, hmacKey, aesKey, salt);
    }

    // ==================== DUMP ====================
    async dump() {
        // Create verification signature
        const verifySig = await subtle.sign(
            "HMAC",
            this.hmacKey,
            stringToBuffer("verify")
        );

        // Build representation object
        const reprObj = {
            salt: encodeBuffer(this.salt),
            kvs: this.kvs,
            reverse: this.reverse,   
            verify: encodeBuffer(verifySig)
        };

        const json = JSON.stringify(reprObj);
        const hashBuf = await subtle.digest("SHA-256", stringToBuffer(json));
        const hash = encodeBuffer(hashBuf);

        return [json, hash];
    }

    // ==================== LOAD ====================
    static async load(password, repr, trustedHash) {
        let data;

        try {
            data = JSON.parse(repr);
        } catch {
            throw "Invalid JSON representation";
        }

        if (!data.salt || !data.kvs)
            throw "Missing salt or kvs";

        // rollback protection
        if (trustedHash !== undefined) {
            const computed = await subtle.digest("SHA-256", stringToBuffer(repr));
            if (encodeBuffer(computed) !== trustedHash)
                throw "Rollback detected: hash mismatch";
        }

        const saltBuf = decodeBuffer(data.salt);
        const masterKey = await deriveMasterKey(password, saltBuf);
        const hmacKey = await deriveHmacKey(masterKey);
        const aesKey = await deriveAesKey(masterKey);

        // verify password
        const expectedSig = await subtle.sign("HMAC", hmacKey, stringToBuffer("verify"));
        if (encodeBuffer(expectedSig) !== data.verify)
            throw "Incorrect password";

        const kc = new Keychain(masterKey, hmacKey, aesKey, saltBuf);
        kc.kvs = data.kvs || {};
        kc.reverse = data.reverse || {};  

        return kc;
    }

    // ==================== SET ====================
    async set(name, value) {
        const domainKey = await computeDomainKey(this.hmacKey, name);
        const encryptedValue = await encryptValue(this.aesKey, value);

        this.kvs[domainKey] = encryptedValue;
        this.reverse[domainKey] = name;
    }

    // ==================== GET ====================
    async get(domain) {
        const dk = await computeDomainKey(this.hmacKey, domain);
        const encrypted = this.kvs[dk];
        if (!encrypted) return null;
        return await decryptValue(this.aesKey, encrypted);
    }

    // ==================== REMOVE ====================
    async remove(domain) {
        const dk = await computeDomainKey(this.hmacKey, domain);
        if (!this.kvs[dk]) return false;

        delete this.kvs[dk];
        delete this.reverse[dk];
        return true;
    }
}

module.exports = Keychain;
