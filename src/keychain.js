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

class Keychain {
    constructor(masterKey, hmacKey, aesKey, salt) {
        this.masterKey = masterKey;
        this.hmacKey = hmacKey;
        this.aesKey = aesKey;
        this.salt = salt;
        this.kvs = {};
        this.reverse = {};     
    }

    // Initialize new vault
    static async init(password) {
        const salt = getRandomBytes(16);
        const masterKey = await deriveMasterKey(password, salt);
        const hmacKey = await deriveHmacKey(masterKey);
        const aesKey = await deriveAesKey(masterKey);

        return new Keychain(masterKey, hmacKey, aesKey, salt);
    }

    // Dump vault to JSON + hash
    async dump() {
        // verification signature
        const verifySigBuf = await subtle.sign(
            "HMAC",
            this.hmacKey,
            stringToBuffer("verify")
        );

        const reprObj = {
            salt: encodeBuffer(this.salt),
            kvs: this.kvs,
            reverse: this.reverse,
            verify: encodeBuffer(verifySigBuf)   
        };

        const json = JSON.stringify(reprObj);
        const hashBuf = await subtle.digest("SHA-256", stringToBuffer(json));
        const hash = encodeBuffer(hashBuf);

        return [json, hash];
    }


    // Load vault from JSON + hash
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
            const computedHashBuf = await subtle.digest(
                "SHA-256",
                stringToBuffer(repr)
            );
            const computedHash = encodeBuffer(computedHashBuf);

            if (computedHash !== trustedHash)
                throw "Rollback detected: hash mismatch";
        }

        const saltBuf = decodeBuffer(data.salt);
        const masterKey = await deriveMasterKey(password, saltBuf);
        const hmacKey = await deriveHmacKey(masterKey);
        const aesKey = await deriveAesKey(masterKey);

        // verify HMAC signature
        if (data.verify !== undefined) {
            const expectedBuf = await subtle.sign(
                "HMAC",
                hmacKey,
                stringToBuffer("verify")
            );
            const expected = encodeBuffer(expectedBuf);

            if (expected !== data.verify)
                throw "Incorrect password";
        }

        const kc = new Keychain(masterKey, hmacKey, aesKey, saltBuf);
        kc.kvs = data.kvs || {};
        kc.reverse = data.reverse || {};   

        // final sanity check: decrypt one entry if exists
        const keys = Object.keys(kc.kvs);
        if (keys.length > 0) {
            try {
                await decryptValue(aesKey, kc.kvs[keys[0]]);
            } catch {
                throw "Incorrect password";
            }
        }

        return kc;
    }

    async set(name, value) {
        const domainKey = await computeDomainKey(this.hmacKey, name);
        const encrypted = await encryptValue(this.aesKey, value);

        this.kvs[domainKey] = encrypted;
        this.reverse[domainKey] = name;  // <-- FINAL FIX
    }

    async get(name) {
        const domainKey = await computeDomainKey(this.hmacKey, name);
        const encrypted = this.kvs[domainKey];
        if (!encrypted) return null;
        return await decryptValue(this.aesKey, encrypted);
    }

    async remove(name) {
        const domainKey = await computeDomainKey(this.hmacKey, name);
        if (!(domainKey in this.kvs)) return false;

        delete this.kvs[domainKey];
        delete this.reverse[domainKey];

        return true;
    }
}

module.exports = Keychain;
