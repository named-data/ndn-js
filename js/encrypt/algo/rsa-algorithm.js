/**
 * Copyright (C) 2015 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt src/algo/rsa https://github.com/named-data/ndn-group-encrypt
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU Lesser General Public License is in the file COPYING.
 */

// (This is ported from ndn::gep::algo::Rsa, and named RsaAlgorithm because
// "Rsa" is very short and not all the Common Client Libraries have namespaces.)

var constants = require('constants');
var Crypto = require('../../crypto.js');
var Blob = require('../../util/blob.js').Blob;
var DecryptKey = require('../decrypt-key.js').DecryptKey;
var EncryptKey = require('../encrypt-key.js').EncryptKey;
var EncryptAlgorithmType = require('./encrypt-params.js').EncryptAlgorithmType;
var DerNode = require('../../encoding/der/der-node.js').DerNode;
var OID = require('../../encoding/oid.js').OID;
var PrivateKeyStorage = require('../../security/identity/private-key-storage').PrivateKeyStorage;
var UseSubtleCrypto = require('../../use-subtle-crypto-node.js').UseSubtleCrypto;
var SyncPromise = require('../../util/sync-promise').SyncPromise;
var rsaKeygen = null;
try {
  // This should be installed with: sudo npm install rsa-keygen
  rsaKeygen = require('rsa-keygen');
}
catch (e) {}

/**
 * The RsaAlgorithm class provides static methods to manipulate keys, encrypt
 * and decrypt using RSA.
 * @note This class is an experimental feature. The API may change.
 */
var RsaAlgorithm = function RsaAlgorithm()
{
};

exports.RsaAlgorithm = RsaAlgorithm;

/**
 * Generate a new random decrypt key for RSA based on the given params.
 * @param {RsaKeyParams} params The key params with the key size (in bits).
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the new DecryptKey
 * (containing a PKCS8-encoded private key).
 */
RsaAlgorithm.generateKeyPromise = function(params, useSync)
{
  if (!rsaKeygen)
    return SyncPromise.reject(new Error
      ("Need to install rsa-keygen: sudo npm install rsa-keygen"));

  var keyPair = rsaKeygen.generate(params.getKeySize());
  // Get the PKCS1 private key DER from the PEM string and encode as PKCS8.
  var privateKeyBase64 = keyPair.private_key.toString().replace
    ("-----BEGIN RSA PRIVATE KEY-----", "").replace
    ("-----END RSA PRIVATE KEY-----", "");
  var pkcs1PrivateKeyDer = new Buffer(privateKeyBase64, 'base64');
  var privateKey = PrivateKeyStorage.encodePkcs8PrivateKey
    (pkcs1PrivateKeyDer, new OID(PrivateKeyStorage.RSA_ENCRYPTION_OID),
     new DerNode.DerNull()).buf();

  return SyncPromise.resolve(new DecryptKey(privateKey));
};

/**
 * Generate a new random decrypt key for RSA based on the given params.
 * @param {RsaKeyParams} params The key params with the key size (in bits).
 * @return {DecryptKey} The new decrypt key (containing a PKCS8-encoded private
 * key).
 * @throws {Error} If generateKeyPromise doesn't return a SyncPromise which is
 * already fulfilled.
 */
RsaAlgorithm.generateKey = function(params)
{
  return SyncPromise.getValue(this.generateKeyPromise(params, true));
};

/**
 * Derive a new encrypt key from the given decrypt key value.
 * @param {Blob} keyBits The key value of the decrypt key (PKCS8-encoded private
 * key).
 * @return {EncryptKey} The new encrypt key (DER-encoded public key).
 */
RsaAlgorithm.deriveEncryptKey = function(keyBits)
{
  var rsaPrivateKeyDer = RsaAlgorithm.getRsaPrivateKeyDer(keyBits);

  // Decode the PKCS #1 RSAPrivateKey.
  parsedNode = DerNode.parse(rsaPrivateKeyDer.buf(), 0);
  var rsaPrivateKeyChildren = parsedNode.getChildren();
  var modulus = rsaPrivateKeyChildren[1];
  var publicExponent = rsaPrivateKeyChildren[2];

  // Encode the PKCS #1 RSAPublicKey.
  var rsaPublicKey = new DerNode.DerSequence();
  rsaPublicKey.addChild(modulus);
  rsaPublicKey.addChild(publicExponent);
  var rsaPublicKeyDer = rsaPublicKey.encode();

  // Encode the SubjectPublicKeyInfo.
  var algorithmIdentifier = new DerNode.DerSequence();
  algorithmIdentifier.addChild(new DerNode.DerOid(new OID
    (RsaAlgorithm.RSA_ENCRYPTION_OID)));
  algorithmIdentifier.addChild(new DerNode.DerNull());
  var publicKey = new DerNode.DerSequence();
  publicKey.addChild(algorithmIdentifier);
  publicKey.addChild(new DerNode.DerBitString(rsaPublicKeyDer.buf(), 0));

  return new EncryptKey(publicKey.encode());
};

/**
 * Decrypt the encryptedData using the keyBits according the encrypt params.
 * @param keyBits {Blob} The key value (PKCS8-encoded private key).
 * @param encryptedData {Blob} The data to decrypt.
 * @param params {EncryptParams} This decrypts according to
 * params.getAlgorithmType().
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the decrypted Blob.
 */
RsaAlgorithm.decryptPromise = function(keyBits, encryptedData, params, useSync)
{
  if (UseSubtleCrypto() && !useSync &&
      // Crypto.subtle doesn't implement PKCS1 padding.
      params.getAlgorithmType() != EncryptAlgorithmType.RsaPkcs) {
    if (params.getAlgorithmType() == EncryptAlgorithmType.RsaOaep) {
      return crypto.subtle.importKey
        ("pkcs8", keyBits.buf(), { name: "RSA-OAEP", hash: {name: "SHA-1"} },
         false, ["decrypt"])
      .then(function(privateKey) {
        return crypto.subtle.decrypt
          ({ name: "RSA-OAEP" }, privateKey, encryptedData.buf());
      })
      .then(function(result) {
        return Promise.resolve(new Blob(new Uint8Array(result), false));
      });
    }
    else
      return Promise.reject(new Error("unsupported padding scheme"));
  }
  else {
    // keyBits is PKCS #8 but we need the inner RSAPrivateKey.
    var rsaPrivateKeyDer = RsaAlgorithm.getRsaPrivateKeyDer(keyBits);

    // Encode the key DER as a PEM private key as needed by Crypto.
    var keyBase64 = rsaPrivateKeyDer.buf().toString('base64');
    var keyPem = "-----BEGIN RSA PRIVATE KEY-----\n";
    for (var i = 0; i < keyBase64.length; i += 64)
      keyPem += (keyBase64.substr(i, 64) + "\n");
    keyPem += "-----END RSA PRIVATE KEY-----";

    var padding;
    if (params.getAlgorithmType() == EncryptAlgorithmType.RsaPkcs)
      padding = constants.RSA_PKCS1_PADDING;
    else if (params.getAlgorithmType() == EncryptAlgorithmType.RsaOaep)
      padding = constants.RSA_PKCS1_OAEP_PADDING;
    else
      return SyncPromise.reject(new Error("unsupported padding scheme"));

    try {
      // In Node.js, privateDecrypt requires version v0.12.
      return SyncPromise.resolve(new Blob
        (Crypto.privateDecrypt({ key: keyPem, padding: padding }, encryptedData.buf()),
         false));
    } catch (err) {
      return SyncPromise.reject(err);
    }
  }
};

/**
 * Decrypt the encryptedData using the keyBits according the encrypt params.
 * @param keyBits {Blob} The key value (PKCS8-encoded private key).
 * @param encryptedData {Blob} The data to decrypt.
 * @param params {EncryptParams} This decrypts according to
 * params.getAlgorithmType().
 * @return {Blob} The decrypted data.
 * @throws {Error} If decryptPromise doesn't return a SyncPromise which is
 * already fulfilled.
 */
RsaAlgorithm.decrypt = function(keyBits, encryptedData, params)
{
  return SyncPromise.getValue(this.decryptPromise
    (keyBits, encryptedData, params, true));
};

/**
 * Encrypt the plainData using the keyBits according the encrypt params.
 * @param keyBits {Blob} The key value (DER-encoded public key).
 * @param plainData {Blob} The data to encrypt.
 * @param params {EncryptParams} This encrypts according to
 * params.getAlgorithmType().
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the encrypted Blob.
 */
RsaAlgorithm.encryptPromise = function(keyBits, plainData, params, useSync)
{
  if (UseSubtleCrypto() && !useSync &&
      // Crypto.subtle doesn't implement PKCS1 padding.
      params.getAlgorithmType() != EncryptAlgorithmType.RsaPkcs) {
    if (params.getAlgorithmType() == EncryptAlgorithmType.RsaOaep) {
      return crypto.subtle.importKey
        ("spki", keyBits.buf(), { name: "RSA-OAEP", hash: {name: "SHA-1"} },
         false, ["encrypt"])
      .then(function(publicKey) {
        return crypto.subtle.encrypt
          ({ name: "RSA-OAEP" }, publicKey, plainData.buf());
      })
      .then(function(result) {
        return Promise.resolve(new Blob(new Uint8Array(result), false));
      });
    }
    else
      return Promise.reject(new Error("unsupported padding scheme"));
  }
  else {
    // Encode the key DER as a PEM public key as needed by Crypto.
    var keyBase64 = keyBits.buf().toString('base64');
    var keyPem = "-----BEGIN PUBLIC KEY-----\n";
    for (var i = 0; i < keyBase64.length; i += 64)
      keyPem += (keyBase64.substr(i, 64) + "\n");
    keyPem += "-----END PUBLIC KEY-----";

    var padding;
    if (params.getAlgorithmType() == EncryptAlgorithmType.RsaPkcs)
      padding = constants.RSA_PKCS1_PADDING;
    else if (params.getAlgorithmType() == EncryptAlgorithmType.RsaOaep)
      padding = constants.RSA_PKCS1_OAEP_PADDING;
    else
      return SyncPromise.reject(new Error("unsupported padding scheme"));

    try {
      // In Node.js, publicEncrypt requires version v0.12.
      return SyncPromise.resolve(new Blob
        (Crypto.publicEncrypt({ key: keyPem, padding: padding }, plainData.buf()),
         false));
    } catch (err) {
      return SyncPromise.reject(err);
    }
  }
};

/**
 * Encrypt the plainData using the keyBits according the encrypt params.
 * @param keyBits {Blob} The key value (DER-encoded public key).
 * @param plainData {Blob} The data to encrypt.
 * @param params {EncryptParams} This encrypts according to
 * params.getAlgorithmType().
 * @return {Blob} The encrypted data.
 * @throws {Error} If encryptPromise doesn't return a SyncPromise which is
 * already fulfilled.
 */
RsaAlgorithm.encrypt = function(keyBits, plainData, params)
{
  return SyncPromise.getValue(this.encryptPromise
    (keyBits, plainData, params, true));
};

/**
 * Decode the PKCS #8 private key, check that the algorithm is RSA, and return
 * the inner RSAPrivateKey DER.
 * @param {Blob} The DER-encoded PKCS #8 private key.
 * @param {Blob} The DER-encoded RSAPrivateKey.
 */
RsaAlgorithm.getRsaPrivateKeyDer = function(pkcs8PrivateKeyDer)
{
  var parsedNode = DerNode.parse(pkcs8PrivateKeyDer.buf(), 0);
  var pkcs8Children = parsedNode.getChildren();
  var algorithmIdChildren = DerNode.getSequence(pkcs8Children, 1).getChildren();
  var oidString = algorithmIdChildren[0].toVal();

  if (oidString != RsaAlgorithm.RSA_ENCRYPTION_OID)
    throw new Error("The PKCS #8 private key is not RSA_ENCRYPTION");

  return pkcs8Children[2].getPayload();
};

RsaAlgorithm.RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1";
