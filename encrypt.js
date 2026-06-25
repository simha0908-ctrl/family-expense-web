// Encrypts an HTML file with AES-256-GCM (PBKDF2-SHA256, 200k iters)
// so it can be decrypted in-browser via Web Crypto. The password is NOT
// stored anywhere; only the ciphertext is written into the output page.
//
// Usage: node encrypt.js <password> <plaintext.html> <output.html> [title]
const fs = require("fs");
const crypto = require("crypto");

const [, , password, srcPath, outPath, titleArg] = process.argv;
if (!password || !srcPath || !outPath) {
  console.error("usage: node encrypt.js <password> <src.html> <out.html> [title]");
  process.exit(1);
}

const ITER = 200000;
const plaintext = fs.readFileSync(srcPath);
const salt = crypto.randomBytes(16);
const iv = crypto.randomBytes(12);
const key = crypto.pbkdf2Sync(password, salt, ITER, 32, "sha256");

const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
const tag = cipher.getAuthTag();
// Web Crypto expects ciphertext||tag
const payload = Buffer.concat([enc, tag]).toString("base64");

const title = titleArg || "보호된 페이지";
const tpl = fs.readFileSync(__dirname + "/lock.template.html", "utf8");
const out = tpl
  .replace(/__TITLE__/g, title)
  .replace("__SALT__", salt.toString("base64"))
  .replace("__IV__", iv.toString("base64"))
  .replace("__ITER__", String(ITER))
  .replace("__PAYLOAD__", payload);

fs.writeFileSync(outPath, out);
console.log("encrypted ->", outPath);
