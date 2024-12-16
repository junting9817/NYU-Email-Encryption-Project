/** * Copyright (C) 2012-2019 Mailvelope GmbH * Licensed under the GNU Affero General Public License version 3 */

import * as l10n from '../lib/l10n';
import {dataURL2str, str2Uint8Array, dataURL2base64, MvError} from '../lib/util';
import {
  config as pgpConfig, readMessage as pgpReadMessage, createMessage, readCleartextMessage as pgpReadCleartextMessage,
  readSignature, enums, decrypt as pgpDecrypt, PrivateKey, encrypt as pgpEncrypt, SecretKeyPacket, UserIDPacket, SignaturePacket, SecretSubkeyPacket
} from 'openpgp';
import {readToEnd} from '@openpgp/web-stream-tools';
import * as defaults from './defaults';
import * as prefs from './prefs';
import * as pwdCache from './pwdCache';
import {randomString, symEncrypt} from './crypto';
import * as uiLog from './uiLog';
import {getById as getKeyringById, getKeyringWithPrivKey, syncPublicKeys, getPreferredKeyring} from './keyring';
import {getUserInfo, mapKeys, keyIDfromHex} from './key';
import * as keyringSync from './keyringSync';
import * as trustKey from './trustKey';
import {updateKeyBinding, init as initKeyBinding} from './keyBinding';
import {KEYSERVER_ADDRESS, COMMUNICATION, recordOnboardingStep} from '../lib/analytics';

import {aesGcmEncrypt, generateAesKey} from './crypto';
import {rsaEncryptAesKey} from './openpgpjs';
import {aesGcmDecrypt} from './crypto';
import {rsaDecryptAesKey} from './openpgpjs';

export async function init() {
  await defaults.init();
  await prefs.init();
  pwdCache.init();
  initKeyBinding();
  initOpenPGP();
  await trustKey.init();
}

export function initOpenPGP() {
  pgpConfig.commentString = 'https://mailvelope.com';
  pgpConfig.versionString = `Mailvelope v${defaults.getVersion()}`;
  if (prefs.prefs.security.hide_armored_header) {
    pgpConfig.showVersion = false;
    pgpConfig.showComment = false;
  } else {
    pgpConfig.showVersion = true;
    pgpConfig.showComment = true;
  }
}

/**
 * Generate an HMAC tag for a given payload
 * @param {Uint8Array} data - The data for which to generate the HMAC
 * @param {CryptoKey} data - The data for which to generate the HMAC
 * @returns {Uint8Array} - The generated HMAC tag
 */
async function generateHmac(data, hmacKey) {
  const hmac = await window.crypto.subtle.sign(
    {
      name: 'HMAC',
    },
    hmacKey,
    data
  );
  return new Uint8Array(hmac);
}

/**
 * Verifies an HMAC tag for the given data.
 * @param {Uint8Array} data - The data to verify
 * @param {Uint8Array} hmacTag - The received HMAC tag
 * @param {CryptoKey} hmacKey - The key used to verify the HMAC
 * @returns {boolen} - Whether the HMAC is valid
 */
async function verifyHmac(data, hmacTag, hmacKey) {
  const isValid = await window.crypto.subtle.verify(
    {
      name: 'HMAC',
    },
    hmacKey,
    hmacTag,
    data
  );
  return isValid;
}

/**
 * Decrypt armored PGP message
 * @param  {openpgp.Message} options.message - optional PGP message object
 * @param  {String} options.armored - armored PGP message
 * @param  {String} options.keyringId
 * @param  {Function} options.unlockKey - callback to unlock key
 * @param  {String|Array} options.senderAddress - email address of sender, used to indentify key for signature verification
 * @param  {Boolean} options.selfSigned - message is self signed (decrypt email draft scenario)
 * @return {Promise<Object>} - decryption result {data: String, signatures: Array}
 */
// Max allowed time difference: 5 minutes
export async function decryptMessage({armored, unlockKey, keyringId, uiLogSource, maxTimeDifference = 5 * 60 * 1000}) {
  console.log('[decryptMessage] Starting decryption process...');

  const message = await readMessage({armoredMessage: armored});
  console.log('[decryptMessage] Parsed PGP-armored message;', message);

  const plaintextJson = message.getText();
  console.log('[decryptMessage] Extracted JSON from PGP message:', plaintextJson);

  const encryptedData = JSON.parse(plaintextJson);
  console.log('[decryptMessage] Parsed encrypted data:', encryptedData);

  const ciphertext = new Uint8Array(Object.values(encryptedData.ciphertext));
  const iv = new Uint8Array(Object.values(encryptedData.iv));
  const authTag = new Uint8Array(Object.values(encryptedData.authTag));
  const hmacTag = new Uint8Array(Object.values(encryptedData.hmacTag));

  //const encryptionKeyIds = message.getEncryptionKeyIDs();
  const keyring = await getKeyringWithPrivKey(null,  keyringId);
  console.log('[decryptMessage] Retrieved keyring:', keyring);

  const parsedMessage = await readMessage({armoredMessage: encryptedData.encryptedAESKey});
  console.log('[decryptMessage] Parsed PGP message packets:', parsedMessage.packets);

  const encryptionKeyIds = parsedMessage.getEncryptionKeyIDs();
  console.log('[decryptMessage] Encryption Key IDs:', encryptionKeyIds);

  if (encryptionKeyIds.length === 0) {
    console.log('[decryptMessage] Encryption Key IDs are emtpy');
  }

  const aesKeyRaw = await rsaDecryptAesKey(encryptedData.encryptedAESKey, keyring, encryptionKeyIds, unlockKey);
  console.log('[decryptMessage] aesKeyRaw:', aesKeyRaw);

  const hmacKeyRaw = await rsaDecryptAesKey(encryptedData.encryptedHMACKey, keyring, encryptionKeyIds, unlockKey);
  console.log('[decryptMessage] hmacKeyRaw:', hmacKeyRaw);

  const aesKey = await window.crypto.subtle.importKey(
    'raw',
    new Uint8Array(aesKeyRaw),
    {name: 'AES-GCM'},
    true,
    ['encrypt', 'decrypt']
  );

  const hmacKey = await window.crypto.subtle.importKey(
    'raw',
    new Uint8Array(hmacKeyRaw),
    {name: 'HMAC', hash: 'SHA-256'},
    true,
    ['sign', 'verify']
  );

  const combinedCiphertext = new Uint8Array([
    ...ciphertext,
    ...iv,
    ...authTag,
  ]);

  const isHmacValid = await verifyHmac(combinedCiphertext, hmacTag, hmacKey);
  if (!isHmacValid) {
    throw new Error('HMAC verification failed.');
  }
  console.log('[decryptMessage] HMAC verification passed.');

  const plaintext = await aesGcmDecrypt(
    {
      ciphertext,
      iv,
      authTag,
    },
    aesKey,
  );
  console.log('[decryptMessage] Decrypted message:', plaintext);

  // Parse and validate the payload
  const payload = JSON.parse(plaintext);
  console.log('[decryptMessage] Decrypted paylod:', payload);

  const currentTimestamp = Date.now();
  if (!payload.timestamp || Math.abs(currentTimestamp - payload.timestamp) > maxTimeDifference) {
    throw new Error('Timestamp validation failed.');
  }
  console.log('[decryptMessage] Timestamp validation passed.');

  await syncPublicKeys({keyring, keyIds: encryptionKeyIds, keyringId});

  await logDecryption(uiLogSource, keyring, encryptionKeyIds, null);
  console.log('[decryptMessage] Decryption process complete successfully.');

  return payload.data;
}

/**
 * Add signing key details to signature. Validate if sender identity matches signature.
 * @param {Array} signatures
 * @param {KeyringBase} keyring
 */
async function addSignatureDetails({signatures = [], keyring, senderAddress}) {
  let senderKeys;
  if (senderAddress) {
    // valid sender keys for verification of the message are keys with the sender email address as user ID
    ({[senderAddress]: senderKeys} = await keyring.getKeyByAddress(senderAddress));
  }
  for (const signature of signatures) {
    if (signature.valid === null) {
      continue;
    }
    const signingKey = keyring.keystore.getKeysForId(signature.fingerprint ?? signature.keyId, true);
    if (signingKey) {
      [signature.keyDetails] = await mapKeys(signingKey);
    }
    if (!signature.valid) {
      continue;
    }
    if (senderKeys) {
      if (!senderKeys.length) {
        // we don't have the sender email and therefore the connection between this signature and the sender is uncertain
        signature.uncertainSender = true;
      } else if (!senderKeys.some(key => key.getKeys(keyIDfromHex(signature)).length)) {
        // sender email is not present in user ID of key that created this signature
        signature.senderMismatch = true;
      }
    }
  }
}

export function noKeyFoundError(encryptionKeyIds) {
  const keyId = encryptionKeyIds[0].toHex();
  let errorMsg = l10n.get('message_no_keys', [keyId.toUpperCase()]);
  for (let i = 1; i < encryptionKeyIds.length; i++) {
    errorMsg = `${errorMsg} ${l10n.get('word_or')} ${encryptionKeyIds[i].toHex().toUpperCase()}`;
  }
  return new MvError(errorMsg, 'NO_KEY_FOUND');
}

/**
 * Parse armored PGP message
 * @param  {String} [options.armoredMessage]
 * @param  {Uint8Array} [options.binaryMessage]
 * @return {openpgp.Message}
 */
export async function readMessage({armoredMessage, binaryMessage}) {
  if (!armoredMessage && !binaryMessage) {
    throw new Error('No message to read');
  }
  try {
    return await pgpReadMessage({armoredMessage, binaryMessage});
  } catch (e) {
    console.log('Error in openpgp.readMessage', e);
    if (armoredMessage) {
      throw new MvError(l10n.get('message_read_error', [e]), 'ARMOR_PARSE_ERROR');
    }
    throw new MvError(l10n.get('file_read_error', [e]), 'BINARY_PARSE_ERROR');
  }
}

/**
 * Encrypt PGP message
 * @param {String} options.data - data to be encrypted as string
 * @param {String} options.keyringId
 * @param  {Function} options.unlockKey - callback to unlock key
 * @param {Array<String>} options.encryptionKeyFprs - fingerprint of encryption keys
 * @param {String} options.signingKeyFpr - fingerprint of signing key
 * @param {String} options.uiLogSource - UI source that triggered encryption, used for logging
 * @param {String} [options.filename] - file name set for this message
 * @param {Boolean} [noCache] - if true, no password cache should be used to unlock signing keys
 * @param {Boolean} [allKeyrings] - use all keyrings for public key sync
 * @return {Promise<String>} - armored PGP message
*/
export async function encryptMessage({data, keyringId, encryptionKeyFprs, signingKeyFpr, uiLogSource, filename, noCache, allKeyrings}) {
  console.log('[encryptMessage] Starting encryption process...');

  const keyring = await getKeyringWithPrivKey(signingKeyFpr, keyringId, noCache);
  if (!keyring) {
    throw new Error('No private key found.');
  }
  console.log('[encryptMessage] Retrieved keyring:', keyring);

  await syncPublicKeys({keyring, keyIds: encryptionKeyFprs, keyringId, allKeyrings});
  console.log('[encryptMessage] Synchronized public keys.');

  // Generate a new AES key
  const aesKey = await generateAesKey();
  console.log('[encryptMessage] Generated AES key:', aesKey);
  console.log('[encryptMessage] AES key length:', aesKey.length);

  // Generate a new HMAC key
  const hmacKey = await window.crypto.subtle.generateKey(
    {
      name: 'HMAC',
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify']
  );
  console.log('[encryptMessage] Generated HMAC key:', hmacKey);

  // Add timestamp to the data
  const payload = {
    timestamp: Date.now(),
    data,
  };
  console.log('[encryptMessage] Payload with timestamp:', payload);

  // Encrypt the payload using AES-GCM
  const encryptedMessage = await aesGcmEncrypt(JSON.stringify(payload), aesKey);
  console.log('[encryptMessage] Encrypted message:', encryptedMessage);

  // Generate HMAC for the encrypted data
  const hmacTag = await generateHmac(
    new Uint8Array([
      ...encryptedMessage.ciphertext,
      ...encryptedMessage.iv,
      ...encryptedMessage.authTag,
    ]),
    hmacKey
  );
  console.log('[encrypteMessage] Generated HMAC tag:', hmacTag);

  const aesKeyRaw = await window.crypto.subtle.exportKey('raw', aesKey);
  const hmacKeyRaw = await window.crypto.subtle.exportKey('raw', hmacKey);
  console.log('[encryptMessage] Exported raw AES Key:', aesKeyRaw);
  console.log('[encryptMessage] Exported raw HMAC Key:', hmacKeyRaw);

  const recipientPublicKey = keyring.getKeysByFprs(encryptionKeyFprs)[0].armor();

  //Encrypt the AES key using the recipient's RSA public key
  const encryptedAESKey = await rsaEncryptAesKey(aesKeyRaw, recipientPublicKey);
  const encryptedHMACKey = await rsaEncryptAesKey(hmacKeyRaw, recipientPublicKey);
  console.log('[encryptMessage] Encrypted AES Key:', encryptedAESKey);
  console.log('[encryptMessage] Encrypted HMAC Key:', encryptedHMACKey);

  const jsonData = JSON.stringify({
    ciphertext: encryptedMessage.ciphertext,
    iv: encryptedMessage.iv,
    authTag: encryptedMessage.authTag,
    hmacTag,
    encryptedAESKey,
    encryptedHMACKey,
    filename: filename || '',
  });
  console.log('[encryptMessage] JSON data for PGP message', jsonData);

  const pgpMessage = await createMessage({text: jsonData});
  console.log('[encryptMessage] Created PGP message:', pgpMessage);

  const armoredMessage = pgpMessage.armor();
  console.log('[encryptMessage] PGP-armored message created:', armoredMessage);

  await logEncryption(uiLogSource, keyring, encryptionKeyFprs);
  console.log('[encryptMessage] Encryption provess completed.');
  return armoredMessage;
}

/**
 * Log encryption operation
 * @param  {String} source - source that triggered encryption operation
 * @param {KeyringBase} keyring
 * @param  {Array<String>} keyFprs - fingerprint of used keys
 */
async function logEncryption(source, keyring, keyFprs) {
  if (source) {
    const keys = keyring.getKeysByFprs(keyFprs);
    const recipients = await Promise.all(keys.map(async key => {
      const {userId} = await getUserInfo(key, {allowInvalid: true});
      return userId;
    }));
    uiLog.push(source, 'security_log_encryption_operation', [recipients.join(', ')], false);
    recordOnboardingStep(COMMUNICATION, 'Encryption');
  }
}

/**
 * Log decryption operation
 * @param  {String} source - source that triggered encryption operation
 * @param {KeyringBase} keyring
 * @param  {Array<String>} keyIds - ids of used keys
 * @param  {String|Array} [senderAddress] - email address of sender, used to record keyserver-sent mail.
 */
async function logDecryption(source, keyring, keyIds, senderAddress) {
  if (source) {
    const key = keyring.getPrivateKeyByIds(keyIds);
    const {userId} = await getUserInfo(key, false);
    uiLog.push(source, 'security_log_decryption_operation', [userId], false);
    // Share only whether the sender was the keyserver, not the actual address.
    if (senderAddress && senderAddress.includes(KEYSERVER_ADDRESS)) {
      recordOnboardingStep(COMMUNICATION, 'Decryption (from Keyserver)');
    } else {
      recordOnboardingStep(COMMUNICATION, 'Decryption');
    }
  }
}

async function readCleartextMessage(armoredText) {
  try {
    return await pgpReadCleartextMessage({cleartextMessage: armoredText});
  } catch (e) {
    console.log('createCleartextMessage', e);
    throw new MvError(l10n.get('cleartext_read_error', [e]), 'VERIFY_ERROR');
  }
}

export async function verifyMessage({armored, keyringId, senderAddress, lookupKey}) {
  try {
    const message = await readCleartextMessage(armored);
    const signingKeyIds = message.getSigningKeyIDs();
    if (!signingKeyIds.length) {
      throw new MvError('No signatures found');
    }
    const keyring = getPreferredKeyring(keyringId);
    await syncPublicKeys({keyring, keyIds: signingKeyIds, keyringId});
    if (senderAddress) {
      for (const signingKeyId of signingKeyIds) {
        await acquireSigningKeys({senderAddress, keyring, lookupKey, keyId: signingKeyId});
      }
    }
    const {data, signatures} = await keyring.getPgpBackend().verify({armored, message, keyring});
    await updateKeyBinding(keyring, senderAddress, signatures);
    await addSignatureDetails({signatures, keyring, senderAddress});
    return {data, signatures};
  } catch (e) {
    throw new MvError(l10n.get('verify_error', [e]), 'VERIFY_ERROR');
  }
}

export async function verifyDetachedSignature({plaintext, senderAddress, detachedSignature, keyringId, lookupKey}) {
  try {
    const keyring = getPreferredKeyring(keyringId);
    // determine issuer key id
    const signature = await readSignature({armoredSignature: detachedSignature});
    const sigPackets = signature.packets.filterByTag(enums.packet.signature);
    const issuerKeyIDs = sigPackets.map(sigPacket => sigPacket.issuerKeyID);
    // sync keys to preferred keyring
    await syncPublicKeys({keyring, keyIds: issuerKeyIDs, keyringId});
    // check if we have signing keys in local keyring and if not try key discovery
    await Promise.all(issuerKeyIDs.map(keyId => acquireSigningKeys({senderAddress, keyring, lookupKey, keyId})));
    const {signatures} = await keyring.getPgpBackend().verify({plaintext, detachedSignature, keyring});
    await updateKeyBinding(keyring, senderAddress, signatures);
    await addSignatureDetails({signatures, keyring, senderAddress});
    return {signatures};
  } catch (e) {
    throw new MvError(l10n.get('verify_error', [e]), 'VERIFY_ERROR');
  }
}

async function acquireSigningKeys({senderAddress, keyring, lookupKey, keyId}) {
  let {[senderAddress]: signerKeys} = await keyring.getKeyByAddress(senderAddress, {keyId});
  if (signerKeys) {
    return {
      signerKeys,
      local: true
    };
  }
  // if no keys in local keyring, try key discovery mechanisms
  let rotation;
  if (keyId) {
    ({[senderAddress]: signerKeys} = await keyring.getKeyByAddress(senderAddress));
    if (signerKeys) {
      // potential key rotation event
      rotation = true;
    }
  }
  await lookupKey(rotation);
  ({[senderAddress]: signerKeys} = await keyring.getKeyByAddress(senderAddress, {keyId}));
  return {
    signerKeys: signerKeys || [],
    discovery: true
  };
}

/**
 * Sign plaintext message
 * @param  {String} options.data - plaintext message
 * @param  {String} options.keyringId
 * @param  {[type]} options.unlockKey - callback to unlock key
 * @param  {[type]} options.signingKeyFpr - fingerprint of sign key
 * @return {Promise<String>}
 */
export async function signMessage({data, keyringId, unlockKey, signingKeyFpr}) {
  const keyring = getKeyringWithPrivKey(signingKeyFpr, keyringId);
  if (!keyring) {
    throw new MvError('No private key found', 'NO_PRIVATE_KEY_FOUND');
  }
  try {
    const result = await keyring.getPgpBackend().sign({data, keyring, unlockKey, signingKeyFpr});
    uiLog.push('security_log_editor', 'security_log_sign_operation', [signingKeyFpr.toUpperCase()], false);
    return result;
  } catch (e) {
    console.log('getPgpBackend().sign() error', e);
    throw new MvError(l10n.get('sign_error', [e]), 'SIGN_ERROR');
  }
}

export async function createPrivateKeyBackup(defaultKey, keyPwd = '') {
  // create backup code
  const backupCode = randomString(26);
  const text = `Version: 1\nPwd: ${keyPwd}\n`;
  let msg = await createMessage({text});
  // append key to message
  msg.packets = msg.packets.concat(defaultKey.toPacketList());
  // symmetrically encrypt with backup code
  msg = await symEncrypt(msg, backupCode);
  return {backupCode, message: msg.armor()};
}

function parseMetaInfo(txt) {
  const result = {};
  txt.replace(/\r/g, '').split('\n').forEach(row => {
    if (row.length) {
      const keyValue = row.split(/:\s/);
      result[keyValue[0]] = keyValue[1];
    }
  });
  return result;
}

export async function restorePrivateKeyBackup(armoredBlock, code) {
  let message = await pgpReadMessage({armoredMessage: armoredBlock});
  if (!(message.packets.length === 2 &&
        message.packets[0].constructor.tag === enums.packet.symEncryptedSessionKey && // Symmetric-Key Encrypted Session Key Packet
        message.packets[0].sessionKeyAlgorithm === enums.symmetric.aes256 &&
        (message.packets[0].sessionKeyEncryptionAlgorithm === null || message.packets[0].sessionKeyEncryptionAlgorithm === enums.symmetric.aes256) &&
        message.packets[1].constructor.tag === enums.packet.symEncryptedIntegrityProtectedData // Sym. Encrypted Integrity Protected Data Packet
  )) {
    throw new MvError('Illegal private key backup structure.');
  }
  try {
    message = await message.decrypt(null, [code], undefined, undefined, {...pgpConfig, additionalAllowedPackets: [SecretKeyPacket, UserIDPacket, SignaturePacket, SecretSubkeyPacket]});
  } catch (e) {
    throw new MvError('Could not decrypt message with this restore code', 'WRONG_RESTORE_CODE');
  }
  // extract password
  const metaInfo = await readToEnd(message.getText());
  const pwd = parseMetaInfo(metaInfo).Pwd;
  // remove literal data packet
  const keyPackets = await readToEnd(message.packets.stream, _ => _);
  const privKey =  new PrivateKey(keyPackets);
  return {key: privKey, password: pwd};
}

/**
 * @param  {openpgp.key.Key} key - key to decrypt and verify signature
 * @param  {openpgp.Message} message - sync packet
 * @return {Promise<Object,Error>}
 */
export async function decryptSyncMessage(key, message) {
  const msg = await pgpDecrypt({message, decryptionKeys: key, verificationKeys: key});
  // check signature
  const [sig] = msg.signatures;
  try {
    await sig.verified;
    await key.getSigningKey(sig.keyID);
  } catch (e) {
    throw new Error('Signature of synced keyring is invalid');
  }
  const syncData = JSON.parse(msg.data);
  const publicKeys = [];
  const changeLog = {};
  let fingerprint;
  for (fingerprint in syncData.insertedKeys) {
    publicKeys.push({
      type: 'public',
      armored: syncData.insertedKeys[fingerprint].armored
    });
    changeLog[fingerprint] = {
      type: keyringSync.INSERT,
      time: syncData.insertedKeys[fingerprint].time
    };
  }
  for (fingerprint in syncData.deletedKeys) {
    changeLog[fingerprint] = {
      type: keyringSync.DELETE,
      time: syncData.deletedKeys[fingerprint].time
    };
  }
  return {
    changeLog,
    keys: publicKeys
  };
}

/**
 * @param  {Key} key - used to sign and encrypt the package
 * @param  {Object} changeLog
 * @param  {String} keyringId - selects keyring for the sync
 * @return {Promise<Object, Error>} - the encrypted message and the own public key
 */
export async function encryptSyncMessage(key, changeLog, keyringId) {
  let syncData = {};
  syncData.insertedKeys = {};
  syncData.deletedKeys = {};
  const keyStore = getKeyringById(keyringId).keystore;
  keyStore.publicKeys.keys.forEach(pubKey => {
    convertChangeLog(pubKey, changeLog, syncData);
  });
  keyStore.privateKeys.keys.forEach(privKey => {
    convertChangeLog(privKey.toPublic(), changeLog, syncData);
  });
  for (const fingerprint in changeLog) {
    if (changeLog[fingerprint].type === keyringSync.DELETE) {
      syncData.deletedKeys[fingerprint] = {
        time: changeLog[fingerprint].time
      };
    }
  }
  syncData = JSON.stringify(syncData);
  const message = await createMessage({text: syncData});
  return pgpEncrypt({message, encryptionKeys: key, signingKeys: key});
}

function convertChangeLog(key, changeLog, syncData) {
  const fingerprint = key.getFingerprint();
  const logEntry = changeLog[fingerprint];
  if (!logEntry) {
    console.log(`Key ${fingerprint} in keyring but not in changeLog.`);
    return;
  }
  if (logEntry.type === keyringSync.INSERT) {
    syncData.insertedKeys[fingerprint] = {
      armored: key.armor(),
      time: logEntry.time
    };
  } else if (logEntry.type === keyringSync.DELETE) {
    console.log(`Key ${fingerprint} in keyring but has DELETE in changeLog.`);
  } else {
    console.log('Invalid changeLog type:', logEntry.type);
  }
}

/**
 * Encrypt file
 * @param  {Object} options.plainFile - {content, name} with contant as dataURL and name as filename
 * @param  {Array<String>} options.encryptionKeyFprs - fingerprint of encryption keys
 * @param  {Boolean} options.armor - request the output as armored block
 * @return {String} - encrypted file as armored block or JS binary string
 */
export async function encryptFile({plainFile, keyringId, unlockKey, encryptionKeyFprs, signingKeyFpr, uiLogSource, armor, noCache, allKeyrings}) {
  const keyring = getKeyringWithPrivKey(signingKeyFpr, keyringId, noCache);
  if (!keyring) {
    throw new MvError('No private key found', 'NO_PRIVATE_KEY_FOUND');
  }
  await syncPublicKeys({keyring, keyIds: encryptionKeyFprs, keyringId, allKeyrings});
  try {
    const result = await keyring.getPgpBackend().encrypt({dataURL: plainFile.content, keyring, unlockKey, encryptionKeyFprs, signingKeyFpr, armor, filename: plainFile.name});
    await logEncryption(uiLogSource, keyring, encryptionKeyFprs);
    return result;
  } catch (error) {
    console.log('pgpmodel.encryptFile() error', error);
    throw new MvError(l10n.get('encrypt_error', [error.message]), 'NO_KEY_FOUND');
  }
}

/**
 * Decrypt File
 * @param  {Object} encryptedFile - {content, name} with contant as dataURL and name as filename
 * @param  {Function} unlockKey - callback to unlock key
 * @return {Object<data, signatures, filename>} - data as JS binary string
 */
export async function decryptFile({encryptedFile, unlockKey, uiLogSource}) {
  let armoredMessage;
  let binaryMessage;
  try {
    const content = dataURL2str(encryptedFile.content);
    if (/^-----BEGIN PGP MESSAGE-----/.test(content)) {
      armoredMessage = content;
    } else {
      binaryMessage = str2Uint8Array(content);
    }
    const message = await readMessage({armoredMessage, binaryMessage});
    const encryptionKeyIds = message.getEncryptionKeyIDs();
    const keyring = getKeyringWithPrivKey(encryptionKeyIds);
    if (!keyring) {
      throw noKeyFoundError(encryptionKeyIds);
    }
    const result = await keyring.getPgpBackend().decrypt({base64: () => dataURL2base64(encryptedFile.content), message, keyring, unlockKey: options => unlockKey({message, ...options}), encryptionKeyIds, format: 'binary'});
    await logDecryption(uiLogSource, keyring, encryptionKeyIds);
    if (!result.filename) {
      result.filename = encryptedFile.name.slice(0, -4);
    }
    const sigKeyIds = result.signatures.map(sig => sig.fingerprint || sig.keyId);
    // sync public keys for the signatures
    await syncPublicKeys({keyring, keyIds: sigKeyIds});
    await addSignatureDetails({signatures: result.signatures, keyring});
    return result;
  } catch (error) {
    console.log('pgpModel.decryptFile() error', error);
    throw error;
  }
}
