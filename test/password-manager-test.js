"use strict";

let expect = require("expect.js");
const  Keychain  = require("../password-manager");
const utils = require("../src/crypto-utils");

function expectReject(promise) {
    return promise.then(
        (result) =>
            expect().fail(
                `Expected failure, but function returned ${result}`
            ),
        () => {}
    );
}

describe("Password Manager - Full Test Suite", function () {
    this.timeout(10000);

    // Initialization
    describe("Initialization", function () {
        it("should initialize a new keychain with a password", async function () {
            const kc = await Keychain.init("password123!");
            expect(kc).to.be.an("object");
            expect(kc).to.have.property("salt");
        });

        it("should generate different salts for different instances", async function () {
            const kc1 = await Keychain.init("password123!");
            const kc2 = await Keychain.init("password123!");
            expect(kc1.salt).not.to.eql(kc2.salt);
        });
    });

    // Set / Get
    describe("Set & Get functionality", function () {
        let kc;

        beforeEach(async function () {
            kc = await Keychain.init("masterpw");
        });

        it("should set and get a password", async function () {
            await kc.set("example.com", "test123");
            const pw = await kc.get("example.com");
            expect(pw).to.equal("test123");
        });

        it("should set and retrieve multiple passwords", async function () {
            const values = {
                a: "123",
                b: "456",
                c: "789",
            };

            for (let k in values) {
                await kc.set(k, values[k]);
            }

            for (let k in values) {
                expect(await kc.get(k)).to.equal(values[k]);
            }
        });

        it("should return null for non-existent domains", async function () {
            expect(await kc.get("missing.com")).to.be(null);
        });
    });

    // Remove
    describe("Remove functionality", function () {
        let kc;

        beforeEach(async function () {
            kc = await Keychain.init("masterpw");
            await kc.set("example.com", "alpha");
        });

        it("should remove an existing entry", async function () {
            const ok = await kc.remove("example.com");
            expect(ok).to.be(true);
            expect(await kc.get("example.com")).to.be(null);
        });

        it("should return false when removing non-existent domain", async function () {
            const ok = await kc.remove("idontexist.com");
            expect(ok).to.be(false);
        });
    });

    // Serialization / Deserialization
    describe("Serialization (dump/load)", function () {
        it("should dump and restore correctly", async function () {
            const kc = await Keychain.init("password123!");
            await kc.set("example.com", "alpha");
            await kc.set("google.com", "beta");

            const [repr, hash] = await kc.dump();

            const kc2 = await Keychain.load("password123!", repr, hash);
            expect(await kc2.get("example.com")).to.equal("alpha");
            expect(await kc2.get("google.com")).to.equal("beta");
        });

        it("should detect tampering / rollback attack", async function () {
            const kc = await Keychain.init("password123!");
            const [repr, hash] = await kc.dump();

            const tampered = repr.replace("salt", "saaaalt");
            await expectReject(Keychain.load("password123!", tampered, hash));
        });

        it("should work without trusted hash", async function () {
            const kc = await Keychain.init("password123!");
            await kc.set("example.com", "test");

            const [repr] = await kc.dump();
            const kc2 = await Keychain.load("password123!", repr);

            expect(await kc2.get("example.com")).to.equal("test");
        });

        it("should fail with incorrect password", async function () {
            const kc = await Keychain.init("correctpw");
            const [repr, hash] = await kc.dump();

            await expectReject(Keychain.load("wrongpw", repr, hash));
        });
    });

    // Domain Privacy Tests
    describe("Domain Key Privacy", function () {
        it('should not store plaintext domain names in encrypted kvs', async function () {
            const kc = await Keychain.init("password123!");
            await kc.set("example.com", "test123");

            const [repr] = await kc.dump();
            const parsed = JSON.parse(repr);

            // Check only inside kvs, not reverse
            expect(JSON.stringify(parsed.kvs)).not.to.contain("example.com");
        });


        it("should compute the same HMAC for the same domain", async function () {
            const kc = await Keychain.init("password123!");

            const dk1 = await utils.computeDomainKey(
                kc.hmacKey,
                "example.com"
            );
            const dk2 = await utils.computeDomainKey(
                kc.hmacKey,
                "example.com"
            );

            expect(dk1).to.equal(dk2);
        });
    });

    // Security Tests
    describe("Security Checks", function () {
        it("should not store plaintext passwords", async function () {
            const kc = await Keychain.init("masterpw");
            await kc.set("mybank.com", "supersecretpassword");

            const [repr] = await kc.dump();

            expect(repr).not.to.contain("supersecretpassword");
        });

        it("should include a kvs object in the dump", async function () {
            const kc = await Keychain.init("masterpw");
            for (let i = 0; i < 5; i++) {
                await kc.set(`domain${i}`, `pw${i}`);
            }

            const [repr] = await kc.dump();
            const obj = JSON.parse(repr);

            expect(obj).to.have.key("kvs");
            expect(obj.kvs).to.be.an("object");
            expect(Object.keys(obj.kvs).length).to.be(5);
        });
    });
});
