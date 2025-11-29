🔒 Secure Password Manager

This project is an implementation of a secure password manager core library as part of the ICS 3201 Computer Security course. It demonstrates the use of various cryptographic primitives to securely store, manage, and retrieve user passwords.

The core functionality is built in JavaScript, leveraging the SubtleCrypto API for cryptographic operations, and is designed to run in a Node.js environment.

## Core Concepts & Security Features

This password manager is built with a strong emphasis on security, incorporating several key cryptographic concepts to protect user data against common threats.

- **🔑 Master Password Protection**: The entire password database (keychain) is protected by a single, strong master password.

- **Slow Hashing (Key Derivation)**: Uses PBKDF2 with 100,000 iterations and a unique 128-bit salt to derive the master encryption key from the user's password. This makes brute-force and dictionary attacks computationally expensive and slow.

- **Authenticated Encryption (AES-GCM)**: Passwords are encrypted individually using AES-GCM with 256-bit keys. This provides both confidentiality (data is unreadable) and integrity (data cannot be tampered with undetected).

- **Encrypted Domain Lookups**: Domain names (e.g., www.google.com) are not stored in plaintext. Instead, an HMAC of the domain name is used as the key in the key-value store, preventing an attacker from learning which websites the user has accounts for.

- **Password Length Obfuscation**: The implementation defends against information leakage regarding password lengths by padding all passwords to 64 characters before encryption.

- **Swap Attack Defense**: Includes a mechanism to prevent an adversary from swapping the encrypted password of one domain (e.g., www.evil.com) with another (e.g., www.google.com).

- **Rollback Attack Defense**: Uses a SHA-256 checksum of the entire database. This hash can be stored in a trusted location (like a separate flash drive) to verify that the database has not been tampered with or "rolled back" to a previous state by an adversary.

## Setup & Usage

This project is designed to be run using Node.js.

### 1. Installation

Ensure you have Node.js (latest version recommended) and npm installed.

Clone the repository and install the dependencies (e.g., MochaJS for testing):

# Navigate to the project directory

cd Password-Manager

# Install dependencies

npm install prompt-sync clipboardy mocha expect.js 

### 2. Running Tests

The provided starter code includes a test suite to verify functionality and security properties.

To run the tests:

```bash
npm test
```

You should see output showing **18 passing tests** covering:

To use the password manager, you need to type node pm.js in your terminal in the directory of the cloned repo and you will be prompted to create a vault, type init to initialise one and you will need to set a master password eg 123456. You may not see anything appearing on the terminal as your key presses are hidden. once in the CLI of the system use the  command 'help' to view all available commands and how to use them. 

- Initialization & key derivation
- Encryption & decryption
- Multi-domain support
- Remove functionality
- Serialization (dump/load)
- Tampering detection
- Domain privacy protection

## 📋 API Reference

The core logic is implemented in `password-manager.js` and exposes the following API:

### `static async init(password)`

Initializes a new, empty keychain (password manager).

- Generates a new salt and derives the necessary cryptographic keys from the master password.
- **Returns**: A `Keychain` object.

### `static async load(password, representation, trustedDataCheck)`

Loads a keychain from its serialized string representation (a JSON string).

- Validates the master password. Throws an exception if the password is incorrect.
- If `trustedDataCheck` (the SHA-256 hash) is provided, it verifies the integrity of the entire database against rollback attacks. Throws an exception if tampering is detected.
- **Returns**: The deserialized `Keychain` object.

### `async dump()`

Serializes the entire keychain state into a JSON string.

- Computes the SHA-256 hash of the keychain contents.
- **Returns**: An array `[string, string]`, where the first element is the JSON serialization and the second is the SHA-256 hash.

### `async set(name, value)`

- Securely adds or updates a password (`value`) for a given domain (`name`).
- This operation runs in O(1) time.

### `async get(name)`

- Securely retrieves the password for a given domain (`name`).
- **Returns**: The plaintext password string, or `null` if the domain is not found.
- This operation runs in O(1) time.

### `async remove(name)`

- Removes the entry for the specified domain (`name`) from the keychain.
- **Returns**: `true` if the record was found and removed, `false` otherwise.
- This operation runs in O(1) time.

## ⚠️ Disclaimer

**Caveat**: Please do not consider this project as a substitution for a safe, production-ready password manager. There are many more security considerations that were not addressed in this assignment to make this password manager truly secure for real-world use.
