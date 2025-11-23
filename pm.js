"use strict";

const fs = require("fs");
const readline = require("readline");
const { Keychain } = require("./password-manager");


function prompt(question, hide = false) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: hide ? undefined : process.stdout,
      terminal: true,
    });

    if (hide) {
      process.stdout.write(question);
      process.stdin.on("data", (char) => {
        char = char + "";
        if (char.match(/\n|\r|\u0004/)) {
          process.stdout.write("\n");
        } else {
          process.stdout.write("*"); // mask password input
        }
      });
    }

    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}


const VAULT_FILE = "vault.json";


async function initVault() {
  const password = await prompt("Set master password: ", true);
  const kc = await Keychain.init(password);

  const [repr, hash] = await kc.dump();
  fs.writeFileSync(VAULT_FILE, JSON.stringify({ repr, hash }, null, 2));

  console.log("Vault initialized and saved to vault.json");
}

async function loadVault() {
  if (!fs.existsSync(VAULT_FILE)) {
    console.error("No vault.json file found. Run: node pm.js init");
    process.exit(1);
  }

  const file = JSON.parse(fs.readFileSync(VAULT_FILE, "utf8"));
  const password = await prompt("Enter master password: ", true);

  try {
    const kc = await Keychain.load(password, file.repr, file.hash);
    return kc;
  } catch (e) {
    console.error("❌ Failed to load vault:", e);
    process.exit(1);
  }
}

async function setPassword(domain, value) {
  const kc = await loadVault();
  await kc.set(domain, value);

  const [repr, hash] = await kc.dump();
  fs.writeFileSync(VAULT_FILE, JSON.stringify({ repr, hash }, null, 2));

  console.log(`Password saved for ${domain}`);
}

async function getPassword(domain) {
  const kc = await loadVault();
  const result = await kc.get(domain);

  if (result === null) {
    console.log("No password stored for that domain.");
  } else {
    console.log(`Password for ${domain}: ${result}`);
  }
}

async function removePassword(domain) {
  const kc = await loadVault();
  const ok = await kc.remove(domain);

  const [repr, hash] = await kc.dump();
  fs.writeFileSync(VAULT_FILE, JSON.stringify({ repr, hash }, null, 2));

  if (ok) {
    console.log(`Removed password for ${domain}`);
  } else {
    console.log("No such domain found.");
  }
}

async function listDomains() {
  const kc = await loadVault();
  const domains = Object.keys(kc.kvs);

  console.log("Stored domains:");
  for (const d of domains) console.log(" -", d);
}


async function main() {
  const cmd = process.argv[2];

  switch (cmd) {
    case "init":
      await initVault();
      break;

    case "set":
      await setPassword(process.argv[3], process.argv[4]);
      break;

    case "get":
      await getPassword(process.argv[3]);
      break;

    case "remove":
      await removePassword(process.argv[3]);
      break;

    case "list":
      await listDomains();
      break;

    default:
      console.log(`
Password Manager CLI

Usage:
  node pm.js init                      Create a new vault
  node pm.js set <domain> <password>   Store password
  node pm.js get <domain>              Retrieve password
  node pm.js remove <domain>           Delete a password
  node pm.js list                      List stored passwords
`);
  }
}

main();
