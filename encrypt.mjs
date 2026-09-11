// Encrypts details.src.html (gitignored plaintext) into details.html.
// Usage: FO_PASS='the passphrase' node encrypt.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { pbkdf2Sync, randomBytes, createCipheriv } from 'node:crypto';

const ITER = 310000;
const pass = process.env.FO_PASS;
if (!pass) { console.error('set FO_PASS'); process.exit(1); }

const salt = randomBytes(16);
const iv = randomBytes(12);
const key = pbkdf2Sync(pass, salt, ITER, 32, 'sha256');
const c = createCipheriv('aes-256-gcm', key, iv);
const body = Buffer.concat([c.update(readFileSync('details.src.html')), c.final(), c.getAuthTag()]);
const blob = Buffer.concat([salt, iv, body]).toString('base64');

const page = readFileSync('details.html', 'utf8');
const out = page.replace(/(id="blob"[^>]*>)[^<]*(<)/, `$1${blob}$2`);
if (out === page) { console.error('blob slot not found in details.html'); process.exit(1); }
writeFileSync('details.html', out);
console.log(`encrypted ${blob.length} b64 chars, ${ITER} PBKDF2 iterations`);
