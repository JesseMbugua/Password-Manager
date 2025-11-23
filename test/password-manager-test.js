"use strict";

let expect = require('expect.js');
const { Keychain } = require('../password-manager');

function expectReject(promise) {
    return promise.then(
        (result) => expect().fail(`Expected failure, but function returned ${result}`),
        (error) => {},
    );
}

describe('Password Manager - Cryptography Tests', function() {
    this.timeout(5000);

    describe('Initialization', function() {
        it('should initialize a new keychain with password', async function() {
            const kc = await Keychain.init("password123!");
            expect(kc).to.be.an('object');
            expect(kc).to.have.property('salt');
        });

        it('should generate different salts for different instances', async function() {
            const kc1 = await Keychain.init("password123!");
            const kc2 = await Keychain.init("password123!");
            expect(kc1.salt).not.to.eql(kc2.salt);
        });
    });

    describe('Encryption & Decryption', function () {
        let kc;
        beforeEach(async function () {
            kc = await Keychain.init("password123!");
        });

        it('should set and get a password', async function () {
            await kc.set("example.com", "test123");
            const result = await kc.get("example.com");
            expect(result).to.equal("test123");
        });
    });

    describe('Remove functionality', function () {
        let kc;
        beforeEach(async function () {
            kc = await Keychain.init("password123!");
            await kc.set("example.com", "test123");
        });

        it('should remove an existing entry', async function () {
            const removed = await kc.remove("example.com");
            expect(removed).to.be(true);
            const result = await kc.get("example.com");
            expect(result).to.be(null);
        });
    });

    describe('Serialization (dump/load)', function () {
        it('should serialize and deserialize keychain', async function () {
            const kc = await Keychain.init("password123!");
            await kc.set("example.com", "test123");

            const [repr, hash] = await kc.dump();
            const kc2 = await Keychain.load("password123!", repr, hash);
            const pw = await kc2.get("example.com");
            expect(pw).to.equal("test123");
        });

        it('should detect tampering (rollback attack)', async function () {
            const kc = await Keychain.init("password123!");
            const [repr, hash] = await kc.dump();

            const tampered = repr.replace("{", "{0");
            await expectReject(Keychain.load("password123!", tampered, hash));
        });

        it('should work without trusted hash (no rollback protection)', async function () {
            const kc = await Keychain.init("password123!");
            const [repr] = await kc.dump();
            const kc2 = await Keychain.load("password123!", repr);
            expect(kc2).to.be.an('object');
        });

        it('should fail with wrong password', async function () {
            const kc = await Keychain.init("password123!");
            const [repr, hash] = await kc.dump();
            await expectReject(Keychain.load("wrongpass", repr, hash));
        });
    });

    describe('Domain Key Privacy', function () {
        it('should hash domain names (no plaintext domains in kvs)', async function () {
            const kc = await Keychain.init("password123!");
            await kc.set("example.com", "test123");
            const [repr, _] = await kc.dump();

            expect(repr).not.to.contain("example.com");
        });

        it('should produce same hash for same domain', async function () {
            const kc = await Keychain.init("password123!");

            const dk1 = await kc.hmacKey.sign
            await kc.set("example.com", "test123");
        });
    });
});
