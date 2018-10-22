/**
 * Copyright (C) 2015-2018 Regents of the University of California.
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

/** @ignore */
var cryptoConstants = require('crypto').constants; /** @ignore */
var Crypto = require('../../crypto.js'); /** @ignore */
var Blob = require('../../util/blob.js').Blob; /** @ignore */
var DecryptKey = require('../decrypt-key.js').DecryptKey; /** @ignore */
var EncryptKey = require('../encrypt-key.js').EncryptKey; /** @ignore */
var EncryptAlgorithmType = require('./encrypt-params.js').EncryptAlgorithmType; /** @ignore */
var DerNode = require('../../encoding/der/der-node.js').DerNode; /** @ignore */
var OID = require('../../encoding/oid.js').OID; /** @ignore */
var PrivateKeyStorage = require('../../security/identity/private-key-storage.js').PrivateKeyStorage; /** @ignore */
var UseSubtleCrypto = require('../../use-subtle-crypto-node.js').UseSubtleCrypto; /** @ignore */
var SyncPromise = require('../../util/sync-promise.js').SyncPromise; /** @ignore */
var PublicKey = require('../../security/certificate/public-key.js').PublicKey; /** @ignore */
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
 * @constructor
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
  if (UseSubtleCrypto() && !useSync) {
    return crypto.subtle.generateKey
      ({ name: "RSASSA-PKCS1-v1_5", modulusLength: params.getKeySize(),
         publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
         hash: {name: "SHA-256"} },
       true, ["sign", "verify"])
    .then(function(key) {
      // Export the private key to DER.
      return crypto.subtle.exportKey("pkcs8", key.privateKey);
    })
    .then(function(pkcs8Der) {
      return Promise.resolve(new DecryptKey
        (new Blob(new Uint8Array(pkcs8Der), false)));
    });
  }
  else {
    if (!rsaKeygen)
      return SyncPromise.reject(new Error
        ("Need to install rsa-keygen: sudo npm install rsa-keygen"));

    try {
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
    } catch (err) {
      return SyncPromise.reject(err);
    }
  }
};

/**
 * Generate a new random decrypt key for RSA based on the given params.
 * @param {RsaKeyParams} params The key params with the key size (in bits).
 * @return {DecryptKey} The new decrypt key (containing a PKCS8-encoded private
 * key).
 * @throws Error If generateKeyPromise doesn't return a SyncPromise which is
 * already fulfilled.
 */
RsaAlgorithm.generateKey = function(params)
{
  return SyncPromise.getValue(RsaAlgorithm.generateKeyPromise(params, true));
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
  var parsedNode = DerNode.parse(rsaPrivateKeyDer.buf(), 0);
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
    (PrivateKeyStorage.RSA_ENCRYPTION_OID)));
  algorithmIdentifier.addChild(new DerNode.DerNull());
  var publicKey = new DerNode.DerSequence();
  publicKey.addChild(algorithmIdentifier);
  publicKey.addChild(new DerNode.DerBitString(rsaPublicKeyDer.buf(), 0));

  return new EncryptKey(publicKey.encode());
};

/**
 * Decrypt the encryptedData using the keyBits according the encrypt params.
 * @param {Blob} keyBits The key value (PKCS8-encoded private key).
 * @param {Blob} encryptedData The data to decrypt.
 * @param {EncryptParams} params This decrypts according to
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
      padding = cryptoConstants.RSA_PKCS1_PADDING;
    else if (params.getAlgorithmType() == EncryptAlgorithmType.RsaOaep)
      padding = cryptoConstants.RSA_PKCS1_OAEP_PADDING;
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
 * @param {Blob} keyBits The key value (PKCS8-encoded private key).
 * @param {Blob} encryptedData The data to decrypt.
 * @param {EncryptParams} params This decrypts according to
 * params.getAlgorithmType().
 * @return {Blob} The decrypted data.
 * @throws Error If decryptPromise doesn't return a SyncPromise which is
 * already fulfilled.
 */
RsaAlgorithm.decrypt = function(keyBits, encryptedData, params)
{
  return SyncPromise.getValue(RsaAlgorithm.decryptPromise
    (keyBits, encryptedData, params, true));
};

/**
 * Encrypt the plainData using the keyBits according the encrypt params.
 * @param {Blob} keyBits The key value (DER-encoded public key).
 * @param {Blob} plainData The data to encrypt.
 * @param {EncryptParams} params This encrypts according to
 * params.getAlgorithmType().
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the encrypted Blob.
 */
RsaAlgorithm.encryptPromise = function(keyBits, plainData, params, useSync)
{
  var publicKey;
  try {
    publicKey = new PublicKey(keyBits);
  } catch (ex) {
    return SyncPromise.reject(ex);
  }

  return publicKey.encryptPromise(plainData, params.getAlgorithmType(), useSync);
};

/**
 * Encrypt the plainData using the keyBits according the encrypt params.
 * @param {Blob} keyBits The key value (DER-encoded public key).
 * @param {Blob} plainData The data to encrypt.
 * @param {EncryptParams} params This encrypts according to
 * params.getAlgorithmType().
 * @return {Blob} The encrypted data.
 * @throws Error If encryptPromise doesn't return a SyncPromise which is
 * already fulfilled.
 */
RsaAlgorithm.encrypt = function(keyBits, plainData, params)
{
  return SyncPromise.getValue(RsaAlgorithm.encryptPromise
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

  if (oidString != PrivateKeyStorage.RSA_ENCRYPTION_OID)
    throw new Error("The PKCS #8 private key is not RSA_ENCRYPTION");

  return pkcs8Children[2].getPayload();
};
