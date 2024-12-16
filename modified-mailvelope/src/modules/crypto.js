/**
 * Copyright (C) 2015-2017 Mailvelope GmbH
 * Licensed under the GNU Affero General Public License version 3
 */

import {SymEncryptedSessionKeyPacket, PacketList, SymEncryptedIntegrityProtectedDataPacket, Message, enums} from 'openpgp';
//import crypto from 'crypto';

/**
 * Encrypts a message using AES-GCM
 * @param {string} message - The plaintext message to encrypt
 * @param {Buffer} key - A 256-bit AES key
 * @returns {object} - The encrypted data: ciphertext, IV, and authTag
 */
export async function aesGcmEncrypt(plaintext, aesKey) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encodedPlaintext = new TextEncoder().encode(plaintext);

  const encrypted = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
    },
    aesKey,
    encodedPlaintext
  );

  const ciphertext = new Uint8Array(encrypted.slice(0, -16));
  const authTag = new Uint8Array(encrypted.slice(-16));

  console.log('[aesGcmEncrypt] Ciphertext:', ciphertext);
  console.log('[aesGcmEncrypt] Auth Tag:', authTag);

  return {ciphertext, iv, authTag};
}

/**
 * Decrypts a message using AES-GCM
 * @param {object} encryptedData - The encrypted data: ciphertext, IV, and authTag
 * @param {Buffer} key - A 256-bit AES key
 * @returns {string} - The decrypted plaintext message
 */
export async function aesGcmDecrypt({ciphertext, iv, authTag}, aesKey) {
  if (!authTag || authTag.length !== 16) {
    throw new Error('Invalid or missing authentication tag.');
  }

  const combinedCiphertext = new Uint8Array([...ciphertext, ...authTag]);
  console.log('[aesGcmDecrypt] Combined Ciphertext (with auth Tag):', combinedCiphertext);

  const plaintextBuffer = await window.crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: new Uint8Array(iv),
    },
    aesKey,
    combinedCiphertext
  );

  return new TextDecoder().decode(plaintextBuffer);
}

/**
 * Generates a 256-bit AES key (32 bytes)
 * Compatible for both Node.js and browser environments
 * @returns {Uint8Array} - A random 256-bit AES key
 */
export async function generateAesKey() {
  const key = await  window.crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256,
    },
    true,
    ['encrypt', 'decrypt']
  );
  return key;
}

export function randomString(length) {
  let result = '';
  const base = 32;
  const buf = new Uint8Array(length);
  window.crypto.getRandomValues(buf);
  for (let i = 0; i < buf.length; i++) {
    result += (buf[i] % base).toString(base);
  }

  // Add a debug log to verify this function is called
  console.log('[DEBUG] Generated random string: $[result]');
  return result;
}

/**
 * Encrypt the message symmetrically using a passphrase.
 *   https://tools.ietf.org/html/rfc4880#section-3.7.2.2
 * Copyright (C) 2015 Tankred Hase
 * @param {String} passphrase
 * @return {openpgp.Message} new message with encrypted content
 */
export async function symEncrypt(msg, passphrase) {
  if (!passphrase) {
    throw new Error('The passphrase cannot be empty!');
  }
  const sessionKeyAlgorithm = enums.symmetric.aes256;
  const packetlist = new PacketList();
  // create a Symmetric-key Encrypted Session Key (ESK)
  const symESKPacket = new SymEncryptedSessionKeyPacket();
  symESKPacket.version = 4;
  symESKPacket.sessionKeyAlgorithm = sessionKeyAlgorithm;
  // call encrypt one time to init S2K
  await symESKPacket.encrypt('123456');
  symESKPacket.sessionKey = null;
  symESKPacket.encrypted = null;
  // call decrypt to generate the session key
  await symESKPacket.decrypt(passphrase);
  packetlist.push(symESKPacket);
  // create integrity protected packet
  const symEncryptedPacket = new SymEncryptedIntegrityProtectedDataPacket();
  symEncryptedPacket.packets = msg.packets;
  await symEncryptedPacket.encrypt(sessionKeyAlgorithm, symESKPacket.sessionKey);
  packetlist.push(symEncryptedPacket);
  // remove packets after encryption
  symEncryptedPacket.packets = new PacketList();
  return new Message(packetlist);
}

/**
 * Return a secure random number in the specified range
 * @param {Number} from - min of the random number
 * @param {Number} to - max of the random number (max 32bit)
 * @return {Number} - a secure random number
 */
export function getSecureRandom(from, to) {
  let randUint = getSecureRandomUint();
  const bits = ((to - from)).toString(2).length;
  while ((randUint & (Math.pow(2, bits) - 1)) > (to - from)) {
    randUint = getSecureRandomUint();
  }
  return from + (Math.abs(randUint & (Math.pow(2, bits) - 1)));
}

function getSecureRandomUint() {
  const buf = new Uint8Array(4);
  const dv = new DataView(buf.buffer);
  window.crypto.getRandomValues(buf);
  return dv.getUint32(0);
}
