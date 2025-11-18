
// Data storage
class Keychain {
    constructor(masterKey, hmacKey, aesKey, salt) {
        this.masterKey = masterKey;
        this.hmacKey = hmacKey;
        this.aesKey = aesKey;
        this.salt = salt;     // raw buffer
        this.kvs = {};        // required field for autograder
    }

    static async init(password) {
        // Jesse's functions are to be expected
        const salt = getRandomBytes(16);

        const masterKey = await deriveMasterKey(password, salt);
        const hmacKey = await deriveHmacKey(masterKey);
        const aesKey  = await deriveAesKey(masterKey);

        return new Keychain(masterKey, hmacKey, aesKey, salt);
    }

    // serialize current state to JSON + hash
    async dump() {
        const repr = {
            salt: encodeBuffer(this.salt), // Base64
            kvs: this.kvs                 // encrypted entries
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

        if (!data.salt || !data.kvs)
            throw "Missing salt or kvs";

        // Rollback detection
        if (trustedHash !== undefined) {
            const computedHashBuf = await subtle.digest("SHA-256", stringToBuffer(repr));
            const computedHash = encodeBuffer(computedHashBuf);

            if (computedHash !== trustedHash)
                throw "Rollback detected: hash mismatch";
        }

        // Recreate keys
        const saltBuf = decodeBuffer(data.salt);

        const masterKey = await deriveMasterKey(password, saltBuf);
        const hmacKey   = await deriveHmacKey(masterKey);
        const aesKey    = await deriveAesKey(masterKey);

        // Rebuild instance
        const kc = new Keychain(masterKey, hmacKey, aesKey, saltBuf);
        kc.kvs = data.kvs;

        return kc;
    }
}

// Export for autograder
module.exports = Keychain;
