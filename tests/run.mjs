// node tests/run.mjs   (Windows, VS 2022 C++ tools, Node 18+)
// Uses a throwaway key generated for the run.
import { execFileSync, spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtempSync, writeFileSync, readFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const tmp = mkdtempSync(join(tmpdir(), "relsig-"));
const exe = join(tmp, "verify_cli.exe");

const vswhere = join(process.env["ProgramFiles(x86)"], "Microsoft Visual Studio", "Installer", "vswhere.exe");
const vs = execFileSync(vswhere, ["-latest", "-products", "*", "-requires",
  "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"]).toString().trim();
const bat = join(tmp, "build.cmd");
writeFileSync(bat, `@echo off\r\ncall "${vs}\\VC\\Auxiliary\\Build\\vcvars64.bat" >nul || exit /b 1\r\n` +
  `cl /nologo /std:c++20 /W4 /WX /EHsc /O2 /Fo"${tmp}\\\\" /Fe"${exe}" "${join(here, "verify_cli.cpp")}" bcrypt.lib\r\n`);
const b = spawnSync("cmd.exe", ["/c", bat], { encoding: "utf8" });
if (b.status !== 0) { console.error(b.stdout, b.stderr); process.exit(1); }

const keys = () => generateKeyPairSync("ec", { namedCurve: "P-256" });
const hex = (k) => { const j = k.publicKey.export({ format: "jwk" });
  return Buffer.concat([Buffer.from(j.x, "base64url"), Buffer.from(j.y, "base64url")]).toString("hex"); };
const good = keys(), other = keys();
const keyFile = join(tmp, "key.pem");
writeFileSync(keyFile, good.privateKey.export({ type: "pkcs8", format: "pem" }));

const dir = join(tmp, "rel"); mkdirSync(dir);
for (const n of ["app.exe", "core.dll", "ui.zip"]) writeFileSync(join(dir, n), randomBytes(100000));
const signRelease = (version) => JSON.parse(execFileSync(process.execPath,
  [join(here, "..", "tools", "sign-release.mjs"), "--version", version, "--key", keyFile, "--dir", dir]).toString());
const base = signRelease("1.2.3"), older = signRelease("1.2.2");

const check = (text, pub = hex(good), d = dir) => {
  const f = join(tmp, "m.json"); writeFileSync(f, text);
  return spawnSync(exe, [pub, f, d]).status;
};
const mut = (fn) => { const m = structuredClone(base); fn(m); return JSON.stringify(m); };
const evil = randomBytes(100000), evilHash = createHash("sha256").update(evil).digest("hex");
const altDir = (name, bytes) => { const d = mkdtempSync(join(tmp, "alt-"));
  for (const n of ["app.exe", "core.dll", "ui.zip"]) writeFileSync(join(d, n), n === name ? bytes : readFileSync(join(dir, n)));
  return d; };
const orig = readFileSync(join(dir, "core.dll"));

const cases = [
  ["untouched release", 0, () => check(JSON.stringify(base))],
  ["download URL may change", 0, () => check(mut((m) => { m.artifacts["app.exe"].url = "https://mirror.example/a"; }))],
  ["hash replaced", 10, () => check(mut((m) => { m.artifacts["core.dll"].sha256 = evilHash; }))],
  ["size replaced", 10, () => check(mut((m) => { m.artifacts["core.dll"].size++; }))],
  ["huge size does not overflow", 10, () => check(mut((m) => { m.artifacts["core.dll"].size = 9; })
    .replace('"size":9,', '"size":99999999999999999999999,'))],
  ["version replaced", 10, () => check(mut((m) => { m.version = "9.9.9"; }))],
  ["newline injected into version", 10, () => check(mut((m) => { m.version = "1.2.3"; }).replace('"1.2.3"', '"1.2.3\nx=1"'))],
  ["signature from another release", 10, () => check(mut((m) => { m.artifacts_sig = older.artifacts_sig; }))],
  ["signature removed", 10, () => check(mut((m) => { delete m.artifacts_sig; }))],
  ["signature truncated", 10, () => check(mut((m) => { m.artifacts_sig = m.artifacts_sig.slice(0, 40); }))],
  ["signature not base64", 10, () => check(mut((m) => { m.artifacts_sig = "!!!!"; }))],
  ["one artifact missing", 10, () => check(mut((m) => { delete m.artifacts["ui.zip"]; }))],
  ["all artifacts missing (fails closed)", 10, () => check(mut((m) => { delete m.artifacts; }))],
  ["duplicate key placed first", 10, () => check(JSON.stringify(base).replace('"core.dll":{',
    `"core.dll":{"size":${evil.length},"sha256":"${evilHash}"},"core.dll":{`))],
  ["duplicate key last, with swapped file", 11, () => check(JSON.stringify(base).replace('},"artifacts_sig"',
    `,"core.dll":{"size":${evil.length},"sha256":"${evilHash}"}},"artifacts_sig"`), hex(good), altDir("core.dll", evil))],
  ["wrong public key", 10, () => check(JSON.stringify(base), hex(other))],
  ["empty manifest", 10, () => check("")],
  ["HTML error page", 10, () => check("<html>502</html>")],
  ["valid manifest, swapped file", 11, () => check(JSON.stringify(base), hex(good), altDir("core.dll", evil))],
  ["valid manifest, truncated download", 11, () => check(JSON.stringify(base), hex(good), altDir("core.dll", orig.subarray(0, 50000)))],
  ["valid manifest, one bit flipped", 11, () => { const x = Buffer.from(orig); x[777] ^= 1;
    return check(JSON.stringify(base), hex(good), altDir("core.dll", x)); }],
  ["older signed manifest is still accepted (known limit)", 0, () => check(JSON.stringify(older))],
];

let failed = 0;
for (const [name, want, fn] of cases) {
  const got = fn();
  if (got !== want) failed++;
  console.log(`${got === want ? "ok  " : "FAIL"} ${name} (exit ${got}, expected ${want})`);
}
rmSync(tmp, { recursive: true, force: true });
console.log(`${cases.length - failed}/${cases.length} passed`);
process.exit(failed ? 1 : 0);
