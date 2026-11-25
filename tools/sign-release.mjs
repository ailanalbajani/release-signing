#!/usr/bin/env node
// Signs a complete release. Run offline; the private key never goes to a server.
//   node sign-release.mjs --version 1.2.3 --key key.pem --dir release-folder [--out manifest.json]
import { createHash, createPrivateKey, sign } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const FILES = ["app.exe", "core.dll", "ui.zip"]; // same order as release_signature.hpp

const opt = {};
for (let i = 2; i < process.argv.length; i += 2) opt[process.argv[i].replace(/^--/, "")] = process.argv[i + 1];
for (const k of ["version", "key", "dir"]) if (!opt[k]) { console.error(`--${k} is required`); process.exit(1); }
if (!/^[0-9A-Za-z.-]{1,64}$/.test(opt.version)) { console.error("bad version"); process.exit(1); }

const artifacts = {};
let message = `release-v1\nversion=${opt.version}\n`;
for (const name of FILES) {
  const bytes = readFileSync(join(opt.dir, name)); // a missing file aborts: sign everything or nothing
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  artifacts[name] = { size: bytes.length, sha256 };
  message += `${name}|${bytes.length}|${sha256}\n`;
}

// ieee-p1363 = raw 64-byte r||s, the format BCryptVerifySignature expects.
const key = createPrivateKey(readFileSync(opt.key));
const artifacts_sig = sign("sha256", Buffer.from(message), { key, dsaEncoding: "ieee-p1363" }).toString("base64");
const json = JSON.stringify({ version: opt.version, artifacts, artifacts_sig }, null, 2) + "\n";
if (opt.out) writeFileSync(opt.out, json); else process.stdout.write(json);
