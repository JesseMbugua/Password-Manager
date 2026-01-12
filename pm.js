"use strict";

/**
 * CLI for Password Manager
 *
 * Requirements:
 *   npm install prompt-sync
 *   npm install clipboardy
 * 
 * and ofcourse, Node.js 
 *
 * Usage:
 *   node pm.js
 *   pm> help to get commands list
 */

const fs = require("fs");
const path = require("path");
const readline = require("readline");
const { spawn } = require("child_process");
const Keychain = require("./password-manager");
const prompt = require("prompt-sync")({ sigint: true });
const chalk = require("chalk");
const { webcrypto } = require("crypto");
const CONFIG_FILE = path.join(__dirname, "config.js");

const DEFAULT_CONFIG = { 
  autolockMs: 60_000,
  clipboardClearMs: 15_000,
  auditIgnores: {}, 
}

// clipboard 
let clipboardModule = null;
async function copyToClipboard(text) {
  try {
    if (!clipboardModule) clipboardModule = await import("clipboardy");

    if (clipboardModule && clipboardModule.write) {
      await clipboardModule.write(text);
      return;
    }
    if (clipboardModule && clipboardModule.default && clipboardModule.default.write) {
      await clipboardModule.default.write(text);
      return;
    }
  } catch (e) {

  }

  return new Promise((resolve, reject) => {
    const platform = process.platform;
    let proc;
    if (platform === "win32") {
      proc = spawn("clip");
    } else if (platform === "darwin") {
      proc = spawn("pbcopy");
    } else {
      proc = spawn("sh", ["-c", "command -v xclip >/dev/null 2>&1 && xclip -selection clipboard || ( command -v xsel >/dev/null 2>&1 && xsel --clipboard --input )"]);
    }

    if (!proc || !proc.stdin) {
      reject(new Error("No clipboard utility available"));
      return;
    }

    proc.stdin.write(text);
    proc.stdin.end();

    proc.on("error", (err) => reject(err));
    proc.on("close", (code) => {
      if (code === 0) resolve();
      else reject(new Error("Clipboard command failed"));
    });
  });
}
async function scheduleClipboardClear(originalValue, delayMs) {
  if (!clipboardModule) return;
  const api = clipboardModule.default || clipboardModule
  if(!api.read || !api.write) return;

  setTimeout(async () => {
    try {
      const current = await api.read();
      if(current === originalValue) {
        await api.write("");
      }
    } catch {

    }
  }, delayMs)
  
  
}

// config
const VAULT_FILE = "vault.json";
// const AUTOLOCK_MS = 1 * 60 * 1000; // 1 minute inactivity - auto-lock
let config = loadConfig()
const WARNING_BEFORE_MS = 20 * 1000; // 20 seconds -  warning

let kc = null;
let autolockTimer = null;
let warningTimer = null;
let warned = false;
let dataListenerAdded = false;

// ---------------------- Helpers ----------------------

function clearTerminal() {
  process.stdout.write("\x1Bc");
}

function resetAutolock() {
  // clear any existing timers
  if (autolockTimer) {
    clearTimeout(autolockTimer);
    autolockTimer = null;
  }
  if (warningTimer) {
    clearTimeout(warningTimer);
    warningTimer = null;
  }
  warned = false;

  // if no vault loaded, nothing to do
  if (!kc) return;
/*
  // set warning timer (autolock - warning)
  const warnDelay = Math.max(0, AUTOLOCK_MS - WARNING_BEFORE_MS);
  warningTimer = setTimeout(() => {
    if (!kc) return;
    warned = true;
    console.log("\n 20 seconds until auto-lock…");
    rl.prompt();
  }, warnDelay);

  // set autolock timer
  autolockTimer = setTimeout(() => {
    if (!kc) return;
    kc = null;
    warned = false;
    clearTerminal();
    console.log(chalk.red.bold("\nSession timed out. Vault locked."));
    rl.prompt();
  }, AUTOLOCK_MS);
}
*/
if (config.autolockMs === Infinity) return;

const warnDelay = Math.max(
  0,
  config.autolockMs - WARNING_BEFORE_MS
);

warningTimer = setTimeout(() => {
  if (!kc) return;
  warned = true;
  console.log("\n 20 seconds until auto-lock…");
  rl.prompt();
}, warnDelay);

autolockTimer = setTimeout(() => {
  if (!kc) return;
  kc = null;
  warned = false;
  console.log(chalk.red.bold("\nSession timed out. Vault locked."));
  rl.prompt();
}, config.autolockMs);
}
async function saveVault(keychain) {
  const [repr, hash] = await keychain.dump();
  fs.writeFileSync(VAULT_FILE, JSON.stringify({ repr, hash }, null, 2));
}

function safeReadJsonFile(filename) {
  try {
    const txt = fs.readFileSync(filename, "utf8");
    return JSON.parse(txt);
  } catch (e) {
    return null;
  }
}

// config config
function loadConfig() {
  try {
    delete require.cache[require.resolve(CONFIG_FILE)];
    const userConfig = require(CONFIG_FILE);
    return { ...DEFAULT_CONFIG, ...userConfig };
  } catch {
    return { ...DEFAULT_CONFIG };
  }
}

function saveConfig(cfg) {
  const content = `module.exports = ${JSON.stringify(cfg, null, 2)};\n`;
  fs.writeFileSync(CONFIG_FILE, content);
}


/* OLD generatePassword function
function generatePassword(length = 16) {
  const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}<>?/~";
  const bytes = new Uint8Array(length);
  if (webcrypto && webcrypto.getRandomValues) {
    webcrypto.getRandomValues(bytes);
  } else {
    require("crypto").randomFillSync(bytes);
  }
  let out = "";
  for (let i = 0; i < length; i++) out += charset[bytes[i] % charset.length];
  return out;
}
  */

/*
New version. it will meet most password requirements eg:
  - Atleast 1 uppercase character
  - Atleast 1 special character
  - Atleast 1 number
  - Atleast 1 lowercase character

These rules will only be enforced
*/
function generatePassword(length = 16) {

  const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const lower = "abcdefghijklmnopqrstuvwxyz";
  const nums = "1234567890";
  const special = "!@#$%^&*()-_=+[]{}<>?/~";
  const all = upper + lower + nums + special;

  const crypto = require("crypto")
  const bytes = new Uint8Array(length)
  crypto.randomFillSync(bytes);

  if (length < 4) {
    let out = "";
    for (let i = 0; i < length; i++) {
      out += all[bytes[i] % all.length];
    }
   return out;
  }

  let password = [
    upper[bytes[0] % upper.length],
    lower[bytes[1] % lower.length], 
    nums[bytes[2] % nums.length],
    special[bytes[3] % special.length],
  ];
  for(let i = 4; i < length; i++) {
    password.push(all[bytes[i] % all.length]);;
  }

  for(let i = password.length -1; i > 0; i--) {
    const j = bytes[i] % (i + 1);
    [password[i], password[j]] = [password[j], password[i]]
  }
  return password.join("");
}

function generateCode(length = 4 ){
  const charset = "0123456789";
  const bytes = new Uint8Array(length);
  if (webcrypto && webcrypto.getRandomValues) {
    webcrypto.getRandomValues(bytes);
  } else {
    require("crypto").randomFillSync(bytes);
  }
  let out = "";
  for (let i = 0; i < length; i++) out += charset[bytes[i] % charset.length];
  return out;
}

function maskPassword(pw, head = 2, tail = 2) {
  if (pw === "") return "(empty)";
  if (!pw) return "(none)";

  if (pw.length <= head + tail) {
    return "*".repeat(pw.length);
  }

  return (
    pw.slice(0, head) +
    "*".repeat(pw.length - head - tail) +
    pw.slice(-tail)
  );
}
function printAudit(findings) {
  let issues = 0;

  if (findings.empty.length) {
    issues++;
    console.log("\nEmpty passwords:");
    findings.empty.forEach(d => console.log(" -", d));
  }

  if (findings.short.length) {
    issues++;
    console.log("\nShort passwords (< 8 chars):");
    findings.short.forEach(d => console.log(" -", d));
  }

  if (findings.numeric.length) {
    issues++;
    console.log("\nNumeric-only passwords:");
    findings.numeric.forEach(d => console.log(" -", d));
  }

  if (findings.reused.length) {
    issues++;
    console.log("\nReused passwords:");
    findings.reused.forEach(group => {
      console.log(" -", group.join(", "));
    });
  }

  if (issues === 0) {
    console.log(chalk.green("✔ No issues found. Your vault looks good."));
  } else {
    console.log(
      chalk.yellow(
        `\nAudit complete: ${issues} issue type(s) detected.`
      )
    );
  }
}
function isIgnored(domain, rule) {
  return (
    config.auditIgnores?.[domain]?.includes(rule)
  );
}



function promptHidden(text) {
  return prompt.hide(text);
}

function confirmPrompt(question) {
  const r = prompt(`${question} (y/N): `);
  return r && r.toLowerCase() === "y";
}

// print help
function printHelp() {
  console.log(chalk.greenBright(`
Available Commands:
  init                          Create a new vault
  help                          Show this help menu
  set <domain> <password>       Store password
  get <domain>                  Retrieve password or use show <domain> but it is hidden. Some characters are revealed.
  get <domain> --show || show <domain> --show               The --show flag shows the whole password
  show <domain>                 Same as get
  update <domain> <password>    Update password (requires master auth)
  remove <domain>               Delete a password entry
  clear <domain>                Clear the password for a domain (leave domain present)
  clear vault                   Delete entire vault (requires master auth + confirm)
  clear -t                      Clears the terminal
  clear --terminal              ""
  clear --t                     ""
  cls                           ""
  ignore add <domain> <rule>    used to add a domain to an ignored list for the audit not to clock it
  ignore remove <domain> <rule> remove domain from ignored list
  ignore list                   show ignore list
  create  config                Creates a config file
  config restoredefaults        Restores default config settings
  list                          List stored domains (friendly names)
  search <term>                 Search domains by substring
  generate [length]             Generate a secure password (default 16)
  numgen [length]               Generates a numerical code/ pin (default 4)
  copy <domain>                 Copy password to clipboard (tries clipboardy then fallbacks)
  export <file>                 Export encrypted vault file (backup)
  import <file>                 Import encrypted vault file (requires master password)
  unlock                        Unlock the vault
  lock                          Lock the vault (forget loaded keys)
  restart                       Restart the CLI (soft)
  save                          Save vault to disk
  config show                   Shows available configurations
  config autolock <time|off>    Change the autolock timeout. example usage config autolock 6m
  config clipboard <time|off>   Change clipboard clear time. example usage config clipboard 30s
  exit/quit/q/escape            Quit the CLI
`));
}

// ---------------------- Vault load/save ----------------------

async function loadVaultInteractive() {
  if (!fs.existsSync(VAULT_FILE)) return null;

  const file = safeReadJsonFile(VAULT_FILE);
  if (!file || !file.repr || !file.hash) {
    console.log("vault.json is not in the expected format.");
    return null;
  }

  const pw = promptHidden("Master password: ");
  try {
    const loaded = await Keychain.load(pw, file.repr, file.hash);
    loaded.reverse = loaded.reverse || {};
    kc = loaded;
    resetAutolock();
    return loaded;
  } catch (e) {
    console.log("Failed to load vault:", (e && e.toString) ? e.toString() : e);
    return null;
  }
}

// ---------------------- REPL ----------------------

console.log("-----------------------------------");
console.log("🔐 Password Manager CLI");
console.log("-----------------------------------");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: "pm> ",
});

// add single data listener to reset autolock on any keypress
if (!dataListenerAdded) {
  process.stdin.on("data", () => {
    resetAutolock();
  });
  dataListenerAdded = true;
}

(async function startup() {
  kc = await loadVaultInteractive();
  if (!kc) {
    console.log("No existing vault loaded. Type 'init' to create one.");
  } else {
    console.log("Vault loaded.");
  }
  rl.prompt();
})();

// main line handler
rl.on("line", async (line) => {
  resetAutolock();

  const raw = line.trim();
  if (!raw) {
    rl.prompt();
    return;
  }

  const args = raw.split(/\s+/);
  const cmd = args[0].toLowerCase();

  try {
    switch (cmd) {
      case "help":
        printHelp();
        break;

      case "init": {
        if (fs.existsSync(VAULT_FILE)) {
          if (!confirmPrompt("A vault.json already exists. Overwrite?")) {
            console.log("Aborted.");
            break;
          }
        }
        const pw = promptHidden("Set master password: ");
        const confirm = promptHidden("Confirm master password: ");
        if (pw !== confirm) {
          console.log(chalk.red("Passwords do not match. Aborted."));
          break;
        }
        kc = await Keychain.init(pw);
        kc.reverse = kc.reverse || {};
        await saveVault(kc);
        console.log("Vault created.");
        break;
      }

      case "set": {
        if (args.length < 3) {
            console.log("Usage:");
            console.log(" set <domain> <password>");
            console.log(" set <domain> generate <length>");
            console.log(" set <domain> numgen <length>");
            break;
        }

        if (!kc) {
            console.log("No vault loaded. Use 'init' first.");
            break;
        }

        const domain = args[1];
        const mode = args[2];
        let password;

        // ---- set domain generate 10
        if (mode === "generate") {
            const length = parseInt(args[3]);
            if (!length || length < 4) {
                console.log("Password length must be at least 4.");
                break;
            }
            password = generatePassword(length);
        }

        else if (mode === "numgen") {
            const length = parseInt(args[3]);
            if (!length || length < 3) {
                console.log("Number length must be at least 3.");
                break;
            }
            password = generateCode(length);
        }

        else {
            password = args.slice(2).join(" ");
        }

        await kc.set(domain, password);
        await saveVault(kc);
        console.log(`Saved password for ${domain}`);
        break;
    }

      /*
      case "set": {
        if (args.length < 3) {
          console.log("Usage: set <domain> <password> eg set example.com mypassword");
          break;
        }
        if (!kc) {
          console.log("No vault loaded. Use 'init' first.");
          break;
        }
        const domain = args[1];
        const password = args.slice(2).join(" ");
        await kc.set(domain, password);
        await saveVault(kc);
        console.log(`Saved password for ${domain}`);
        break;
      }
      */
/*
      case "get":
      case "show": {
        if (args.length < 2) {
          console.log("Usage: get <domain> eg get example.com");
          break;
        }
        if (!kc) {
          console.log("No vault loaded.");
          break;
        }
        const domain = args[1];
        const pw = await kc.get(domain);
        if (pw === null) console.log("Not found.");
        else console.log(pw);
        break;
      }
        */
      case "get":
      case "show": {
        if (args.length < 2) {
          console.log("Usage: get <domain> [--show]");
          break;
        }
        if (!kc) {
          console.log("No vault loaded.");
          break;
        }

        const domain = args[1];
        const reveal = args.includes("--show");

        const pw = await kc.get(domain);
        if (pw === null) {
          console.log("Not found.");
        } else if (reveal) {
          console.log(pw);
        } else {
          console.log(maskPassword(pw));
        }
        break;
      }


      case "update": {
        if (args.length < 3) {
          console.log("Usage: update <domain> <newpassword> eg update example.com newpassword");
          break;
        }
        if (!kc) {
          console.log("No vault loaded.");
          break;
        }
        const domain = args[1];
        const newpw = args.slice(2).join(" ");

        const checkPw = promptHidden("Re-enter master password: ");
        const file = safeReadJsonFile(VAULT_FILE);
        try {
          await Keychain.load(checkPw, file.repr, file.hash);

          await kc.set(domain, newpw);
          await saveVault(kc);
          console.log(`Updated password for ${domain}`);
        } catch {
          console.log("Incorrect master password. Update aborted.");
        }

        break;
      }

      case "remove": {
        if (args.length < 2) {
          console.log("Usage: remove <domain>");
          break;
        }
        if (!kc) {
          console.log("No vault loaded.");
          break;
        }
        const domain = args[1];
        const ok = await kc.remove(domain);
        if (ok) {
          await saveVault(kc);
          console.log(`Removed ${domain}`);
        } else {
          console.log("No such domain.");
        }
        break;
      }

      case "cls" : {
        clearTerminal();
        break;
      }

      case "clear": {
        if (args.length < 2) {
          console.log("Usage: clear <domain> | clear vault");
          break;
        }
        const target = args[1].toLowerCase();

        if (flag === "-t" || flag ==="--terminal" || flag === "--t"){
          clearTerminal();
          break;
        }
        if (target === "vault") {
          if (!kc) {
            console.log("No vault loaded.");
            break;
          }
          const checkPw = promptHidden("Enter master password to confirm: ");
          try {
            const file = safeReadJsonFile(VAULT_FILE);
            await Keychain.load(checkPw, file.repr, file.hash);

            if (!confirmPrompt("Are you sure you want to DELETE the entire vault?")) {
              console.log("Operation cancelled.");
              break;
            }

            fs.unlinkSync(VAULT_FILE);
            kc = null;
            console.log("Vault deleted.");
          } catch {
            console.log("Incorrect master password. Abort.");
          }
        } else {
          // clear domain password 
          if (!kc) {
            console.log("No vault loaded.");
            break;
          }
          const domain = args[1];
          await kc.set(domain, "");
          await saveVault(kc);
          console.log(`Cleared password for ${domain}`);
        }
        break;
      }

      case "list": {
        if (!kc) {
          console.log("No vault loaded.");
          break;
        }
        const friendly = Object.values(kc.reverse || {});
        console.log("Stored domains:");
        if (friendly.length === 0) {
          console.log("  (none)");
        } else {
          for (const d of friendly) console.log(" -", d);
        }
        break;
      }

      case "config": {
        if (args.length < 2) {
          console.log("Usage:");
          console.log(" config show");
          console.log(" config autolock <time|off>");
          break;
        }

        const sub = args[1];

        if (sub === "show") {
          console.log("Current configuration:");
          console.log(` autolock: ${
            config.autolockMs === Infinity
              ? "off"
              : config.autolockMs + " ms"
          }`);
          console.log(`Clipboard autoclear : ${config.clipboardClearMs === Infinity ? "off" : config.clipboardClearMs + "ms"}`)
          break;
        }

        if (sub === "autolock") {
          const val = args[2];
          if (!val) {
            console.log("Usage: config autolock <5m|30s|off>");
            break;
          }

          if (val === "off") {
            config.autolockMs = Infinity;
          } else {
            const match = val.match(/^(\d+)(s|m|h)$/);
            if (!match) {
              console.log("Invalid time format. Use 30s, 5m, 1h");
              break;
            }

            const n = parseInt(match[1], 10);
            const unit = match[2];

            const mult =
              unit === "s" ? 1000 :
              unit === "m" ? 60_000 :
              3_600_000;

            config.autolockMs = n * mult;
          }

          saveConfig(config);
          console.log("Autolock updated.");
          resetAutolock();
          break;
        }

        console.log("Unknown config option.");
        break;
      }


      case "search": {
        if (!kc) {
          console.log("No vault loaded.");
          break;
        }
        if (args.length < 2) {
          console.log("Usage: search <term> eg search example");
          break;
        }
        const term = args.slice(1).join(" ").toLowerCase();
        const matches = Object.values(kc.reverse || {}).filter((d) =>
          d.toLowerCase().includes(term)
        );
        if (matches.length === 0) {
          console.log("No matches.");
        } else {
          for (const m of matches) console.log(" -", m);
        }
        break;
      }

      case "generate": {
        const len = args.length >= 2 ? parseInt(args[1], 10) || 16 : 16;
        if (len <= 0 || len > 512) {
          console.log("Length must be between 1 and 512. eg generate 20");
          break;
        }
        console.log(generatePassword(len));
        break;
      }
      case "numgen": {
        const len = args.length >= 2 ? parseInt(args[1], 10) || 4 : 4;
          if (len <= 0 || len > 512) {
            console.log("Length must be between 1 and 512. eg numgen 6");
            break;
          }
          console.log(generateCode(len));
          break;
        }
        
      

      case "copy": {
        if (!kc) {
          console.log("No vault loaded.");
          break;
        }
        if (args.length < 2) {
          console.log("Usage: copy <domain> eg copy example.com");
          break;
        }
        const domain = args[1];
        const pw = await kc.get(domain);
        if (pw === null) {
          console.log("No such entry.");
          break;
        }
        try {
          await copyToClipboard(pw);
          console.log("Copied to clipboard! \n Auto clears in 15, think fast!!!");
          scheduleClipboardClear(pw, 15000);
        } catch (e) {
          console.log("Failed to copy to clipboard:", e && e.toString ? e.toString() : e);
        }
        break;
      }
      case "audit": {
        if (!kc) {
          console.log("No vault loaded.");
          break;
        }

        const findings = {
          empty: [],
          short: [],
          numeric: [],
          reused: [],
        };

        const seen = new Map(); 

        for (const domain of Object.values(kc.reverse || {})) {
          const pw = await kc.get(domain);

          if (pw === null) continue;

          if (pw === "") {
            findings.empty.push(domain);
            continue;
          }

          if (pw.length < 8 && !isIgnored(domain, "short")) {
            findings.short.push(domain);
          }


          if (/^\d+$/.test(pw)) {
            findings.numeric.push(domain);
          }

          // reuse detection 
          if (!seen.has(pw)) {
            seen.set(pw, []);
          }
          seen.get(pw).push(domain);
        }

        // collect reused passwords
        for (const [_, domains] of seen.entries()) {
          if (domains.length > 1) {
            findings.reused.push(domains);
          }
        }

        printAudit(findings);
        break;
      }

      case "ignore": {
        const action = args[1];

        if (!action || action === "list") {
          console.log("Audit ignores:");
          if (!Object.keys(config.auditIgnores).length) {
            console.log(" (none)");
          } else {
            for (const [d, rules] of Object.entries(config.auditIgnores)) {
              console.log(` ${d}: ${rules.join(", ")}`);
            }
          }
          break;
        }

        const domain = args[2];
        const rules = args.slice(3);

        if (!domain || !rules.length) {
          console.log("Usage:");
          console.log(" ignore add <domain> <rule>");
          console.log(" ignore remove <domain> <rule>");
          break;
        }

        config.auditIgnores[domain] ||= [];

        if (action === "add") {
          for (const r of rules) {
            if (!config.auditIgnores[domain].includes(r)) {
              config.auditIgnores[domain].push(r);
            }
          }
          saveConfig(config);
          console.log("Ignore rules added.");
          break;
        }

        if (action === "remove") {
          config.auditIgnores[domain] =
            config.auditIgnores[domain].filter(r => r !== rules[0]);

          if (config.auditIgnores[domain].length === 0) {
            delete config.auditIgnores[domain];
          }

          saveConfig(config);
          console.log("Ignore rule removed.");
          break;
        }

        console.log("Unknown ignore command.");
        break;
      }



      case "export": {
        if (args.length < 2) {
          console.log("Usage: export <filename> eg export backup.json");
          break;
        }
        if (!fs.existsSync(VAULT_FILE)) {
          console.log("No vault to export.");
          break;
        }
        const target = args[1];
        fs.copyFileSync(VAULT_FILE, target);
        console.log(`Exported vault to ${target}`);
        break;
      }

      case "import": {
        if (args.length < 2) {
          console.log("Usage: import <filename> eg import backup.json");
          break;
        }
        const filePath = args[1];
        if (!fs.existsSync(filePath)) {
          console.log("File not found.");
          break;
        }
        const file = safeReadJsonFile(filePath);
        if (!file || !file.repr || !file.hash) {
          console.log("File is not a valid vault export.");
          break;
        }
        // require master password for imported vault
        const importPw = promptHidden("Master password for imported vault: ");
        try {
          await Keychain.load(importPw, file.repr, file.hash);
          // replace local vault
          if (fs.existsSync(VAULT_FILE)) {
            if (!confirmPrompt("Overwrite existing vault.json with imported file?")) {
              console.log("Import cancelled.");
              break;
            }
          }
          fs.copyFileSync(filePath, VAULT_FILE);
          kc = await loadVaultInteractive(); // reload using interactive loader
          console.log("Import successful. Vault loaded.");
        } catch {
          console.log("Incorrect master password for imported vault. Import aborted.");
        }
        break;
      }
      case "unlock": {
        if (!fs.existsSync(VAULT_FILE)) {
          console.log("No vault.json found. Use 'init' to create a new vault.");
          break;
        }

        const file = safeReadJsonFile(VAULT_FILE);
        if (!file || !file.repr || !file.hash) {
          console.log("vault.json is corrupted or invalid.");
          break;
        }

        const pw = promptHidden("Master password: ");

        try {
          kc = await Keychain.load(pw, file.repr, file.hash);
          kc.reverse = kc.reverse || {};
          console.log(chalk.greenBright("Vault unlocked."));
          resetAutolock();
        } catch (e) {
          console.log("Incorrect master password.");
        }

        break;
      }


      case "lock": {
        if (!kc) {
          console.log("Vault is already locked.");
          break;
        }
        kc = null;
        clearTerminal();
        console.log("Vault locked.");
        break;
      }

      case "restart": {
        console.log("Restarting CLI...");
        kc = null;

        if (fs.existsSync(VAULT_FILE)) {
          const file = safeReadJsonFile(VAULT_FILE);
          if (file && file.repr && file.hash) {
            console.log("Reloading vault...");
            const pw = promptHidden("Master password: ");
            try {
              kc = await Keychain.load(pw, file.repr, file.hash);
              kc.reverse = kc.reverse || {};
              console.log("Vault reloaded.");
            } catch (e) {
              console.log("Failed to reload vault. You'll need to run 'init' or 'load' manually.");
              kc = null;
            }
          } else {
            console.log("vault.json is corrupted or unreadable.");
          }
        } else {
          console.log("No vault found. Use 'init' to create one.");
        }

        rl.prompt();
        break;
      }

      case "save": {
        if (!kc) {
          console.log("No vault loaded.");
          break;
        }
        await saveVault(kc);
        console.log("Vault saved.");
        break;
      }
      case "create": {
      if (args[1] !== "config") {
        console.log("Usage: create config");
        break;
      }
      if (sub === "restoredefaults") {
        if (!confirmPrompt("Restore config to default settings?")) {
          console.log("Aborted.");
          break;
        }

        saveConfig({ ...DEFAULT_CONFIG });
        config = loadConfig();

        console.log("Configuration restored to defaults.");
        resetAutolock();
        break;
      }


      if (fs.existsSync(CONFIG_FILE)) {
        if (!confirmPrompt("Config file already exists. Overwrite?")) {
          console.log("Aborted.");
          break;
        }
      }

      saveConfig({ ...DEFAULT_CONFIG });
      config = loadConfig();

      console.log("Config file created with default settings.");
      break;
    }

      case "delete-vault": {
        if (!fs.existsSync(VAULT_FILE)) {
            console.log("No vault.json found.");
            break;
        }

        // require password confirmation
        const pw = promptHidden("Enter master password: ");
        const file = safeReadJsonFile(VAULT_FILE);

        try {
            await Keychain.load(pw, file.repr, file.hash); // validate password
        } catch {
            console.log("Incorrect password. Abort.");
            break;
        }

        if (!confirmPrompt(chalk.red.bold("Are you Certain sure you want to DELETE the entire vault? This cannot be undone."))) {
            console.log("Cancelled.");
            break;
        }

        try {
            fs.unlinkSync(VAULT_FILE);
            kc = null;

            if (autolockTimer) clearTimeout(autolockTimer);
            if (warningTimer) clearTimeout(warningTimer);

            console.log("Vault deleted.");
        } catch (e) {
            console.log("Failed to delete vault:", e.toString ? e.toString() : e);
        }

        break;
    }


      case "exit":
      case "quit":
      case "q":
      case "esc":
        console.log("Goodbye.");
        process.exit(0);
        break;

      default:
        console.log("Unknown command. Type 'help'.");
    }
  } catch (err) {
    console.log("Error:", err && err.toString ? err.toString() : err);
  }

  rl.prompt();
});

rl.on("SIGINT", () => {
  console.log("\n(To exit, type 'exit' or press Ctrl+C again.)");
  rl.prompt();
});

process.on("exit", () => {
  if (autolockTimer) clearTimeout(autolockTimer);
  if (warningTimer) clearTimeout(warningTimer);
});
