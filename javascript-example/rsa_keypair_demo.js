const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const keysDirectory = path.resolve(__dirname, '..', 'keys');
const privateKey = fs.readFileSync(path.join(keysDirectory, 'private_key.pem'));
const publicKey = fs.readFileSync(path.join(keysDirectory, 'public_key.pem'));
const message = Buffer.from('RSA key pair test message');

const signature = crypto.sign('sha256', message, {
  key: privateKey,
  padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
  saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN,
});

const signatureIsValid = crypto.verify('sha256', message, {
  key: publicKey,
  padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
  saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN,
}, signature);

if (!signatureIsValid) {
  throw new Error('Signature verification failed');
}
console.log('Signature verification: PASS');

const ciphertext = crypto.publicEncrypt({
  key: publicKey,
  padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
  oaepHash: 'sha256',
}, message);

const plaintext = crypto.privateDecrypt({
  key: privateKey,
  padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
  oaepHash: 'sha256',
}, ciphertext);

if (!plaintext.equals(message)) {
  throw new Error('Decrypted message does not match the original');
}
console.log('Encryption/decryption: PASS');
