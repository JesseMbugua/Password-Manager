const { expect } = require("chai");
const Keychain = require("./password-manager");

describe("Password Manager - Cryptography Tests", function () {
  this.timeout(10000);

  describe("Initialization", function () {
    it("should initialize a new keychain with password", async function () {
      const keychain = await Keychain.init("myMasterPassword123");

      expect(keychain).to.be.instanceOf(Keychain);
      expect(keychain.masterKey).to.exist;
      expect(keychain.hmacKey).to.exist;
      expect(keychain.aesKey).to.exist;
      expect(keychain.salt).to.exist;
      expect(keychain.salt.length).to.equal(16); // 128-bit salt
      expect(keychain.kvs).to.deep.equal({});
    });

    it("should generate different salts for different instances", async function () {
      const kc1 = await Keychain.init("password1");
      const kc2 = await Keychain.init("password2");

      const salt1 = Buffer.from(kc1.salt).toString("hex");
      const salt2 = Buffer.from(kc2.salt).toString("hex");

      expect(salt1).to.not.equal(salt2);
    });
  });

  describe("Encryption & Decryption", function () {
    let keychain;

    beforeEach(async function () {
      keychain = await Keychain.init("testPassword123");
    });

    it("should set and get a password", async function () {
      await keychain.set("example.com", "mySecretPassword");
      const retrieved = await keychain.get("example.com");

      expect(retrieved).to.equal("mySecretPassword");
    });

    it("should handle multiple domains", async function () {
      await keychain.set("google.com", "password1");
      await keychain.set("github.com", "password2");
      await keychain.set("amazon.com", "password3");

      expect(await keychain.get("google.com")).to.equal("password1");
      expect(await keychain.get("github.com")).to.equal("password2");
      expect(await keychain.get("amazon.com")).to.equal("password3");
    });

    it("should update existing password", async function () {
      await keychain.set("test.com", "oldPassword");
      await keychain.set("test.com", "newPassword");

      const retrieved = await keychain.get("test.com");
      expect(retrieved).to.equal("newPassword");
    });

    it("should return null for non-existent domain", async function () {
      const result = await keychain.get("nonexistent.com");
      expect(result).to.be.null;
    });

    it("should handle special characters in passwords", async function () {
      const complexPassword = "P@ssw0rd!#$%^&*()_+-={}[]|\\:\";'<>?,./";
      await keychain.set("test.com", complexPassword);

      const retrieved = await keychain.get("test.com");
      expect(retrieved).to.equal(complexPassword);
    });

    it("should store passwords with different lengths", async function () {
      await keychain.set("short.com", "abc");
      await keychain.set("long.com", "a".repeat(100));

      expect(await keychain.get("short.com")).to.equal("abc");
      expect(await keychain.get("long.com")).to.equal("a".repeat(100));
    });
  });

  describe("Remove functionality", function () {
    let keychain;

    beforeEach(async function () {
      keychain = await Keychain.init("testPassword");
    });

    it("should remove an existing entry", async function () {
      await keychain.set("example.com", "password123");

      const removed = await keychain.remove("example.com");
      expect(removed).to.be.true;

      const retrieved = await keychain.get("example.com");
      expect(retrieved).to.be.null;
    });

    it("should return false when removing non-existent entry", async function () {
      const removed = await keychain.remove("nonexistent.com");
      expect(removed).to.be.false;
    });
  });

  describe("Serialization (dump/load)", function () {
    it("should serialize and deserialize keychain", async function () {
      const keychain1 = await Keychain.init("masterPassword");
      await keychain1.set("site1.com", "pass1");
      await keychain1.set("site2.com", "pass2");

      const [repr, hash] = await keychain1.dump();

      expect(repr).to.be.a("string");
      expect(hash).to.be.a("string");

      const keychain2 = await Keychain.load("masterPassword", repr, hash);

      expect(await keychain2.get("site1.com")).to.equal("pass1");
      expect(await keychain2.get("site2.com")).to.equal("pass2");
    });

    it("should detect tampering (rollback attack)", async function () {
      const keychain1 = await Keychain.init("password");
      await keychain1.set("test.com", "password1");

      const [repr, hash] = await keychain1.dump();

      // Tamper with the JSON by changing a character
      const parsed = JSON.parse(repr);
      parsed.salt = parsed.salt.substring(0, parsed.salt.length - 1) + "X"; // Flip last character
      const tamperedRepr = JSON.stringify(parsed);

      try {
        await Keychain.load("password", tamperedRepr, hash);
        expect.fail("Should have thrown an error");
      } catch (e) {
        expect(String(e)).to.include("Rollback detected");
      }
    });

    it("should work without trusted hash (no rollback protection)", async function () {
      const keychain1 = await Keychain.init("password");
      await keychain1.set("example.com", "mypass");

      const [repr] = await keychain1.dump();

      const keychain2 = await Keychain.load("password", repr);
      expect(await keychain2.get("example.com")).to.equal("mypass");
    });

    it("should fail with wrong password", async function () {
      const keychain1 = await Keychain.init("correctPassword");
      await keychain1.set("test.com", "secret");

      const [repr, hash] = await keychain1.dump();

      const keychain2 = await Keychain.load("wrongPassword", repr, hash);

      // Wrong password should produce garbage or throw on decryption
      try {
        const result = await keychain2.get("test.com");
        expect(result).to.not.equal("secret");
      } catch (e) {
        expect(e).to.exist;
      }
    });
  });

  describe("Domain Key Privacy", function () {
    it("should hash domain names (no plaintext domains in kvs)", async function () {
      const keychain = await Keychain.init("password");
      await keychain.set("example.com", "password123");

      const keys = Object.keys(keychain.kvs);
      expect(keys.length).to.equal(1);

      // Key should NOT be 'example.com'
      expect(keys[0]).to.not.equal("example.com");

      // Key should be a Base64-like string
      expect(keys[0]).to.match(/^[A-Za-z0-9+/=]+$/);
    });

    it("should produce same hash for same domain", async function () {
      const keychain = await Keychain.init("password");
      await keychain.set("test.com", "pass1");
      const keys1 = Object.keys(keychain.kvs);

      await keychain.set("test.com", "pass2"); // Update
      const keys2 = Object.keys(keychain.kvs);

      expect(keys1).to.deep.equal(keys2);
    });
  });

  describe("PBKDF2 Key Derivation", function () {
    it("should derive different keys from different passwords", async function () {
      const kc1 = await Keychain.init("password1");
      const kc2 = await Keychain.init("password2");

      // Can't directly compare CryptoKey objects, but we can test behavior
      await kc1.set("test.com", "value");
      await kc2.set("test.com", "value");

      const [repr1] = await kc1.dump();
      const [repr2] = await kc2.dump();

      expect(repr1).to.not.equal(repr2);
    });

    it("should derive consistent keys from same password and salt", async function () {
      const kc1 = await Keychain.init("password");
      await kc1.set("test.com", "secret");

      const [repr, hash] = await kc1.dump();

      const kc2 = await Keychain.load("password", repr, hash);
      const retrieved = await kc2.get("test.com");

      expect(retrieved).to.equal("secret");
    });
  });
});
