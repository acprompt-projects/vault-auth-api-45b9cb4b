const crypto = require('crypto');

const ALGO = 'aes-256-gcm';
const KEY_LEN = 32;
const IV_BYTES = 12;
const SALT_BYTES = 32;
const PBKDF2_ITERS = 100_000;

function deriveKey(masterSecret, userSalt) {
  return crypto.pbkdf2Sync(masterSecret, userSalt, PBKDF2_ITERS, KEY_LEN, 'sha512');
}

function generateSalt() {
  return crypto.randomBytes(SALT_BYTES);
}

function encrypt(plaintext, masterSecret, userSalt) {
  const key = deriveKey(masterSecret, userSalt);
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv(ALGO, key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv: iv.toString('base64'), tag: tag.toString('base64'), data: enc.toString('base64') };
}

function decrypt(encObj, masterSecret, userSalt) {
  const key = deriveKey(masterSecret, userSalt);
  const iv = Buffer.from(encObj.iv, 'base64');
  const tag = Buffer.from(encObj.tag, 'base64');
  const data = Buffer.from(encObj.data, 'base64');
  const decipher = crypto.createDecipheriv(ALGO, key, iv);
  decipher.setAuthTag(tag);
  return decipher.update(data) + decipher.final('utf8');
}

module.exports = { encrypt, decrypt, generateSalt, deriveKey, ALGO };