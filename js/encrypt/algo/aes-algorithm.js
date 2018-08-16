/**
 * Copyright (C) 2015-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt src/algo/aes https://github.com/named-data/ndn-group-encrypt
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

// (This is ported from ndn::gep::algo::Aes, and named AesAlgorithm because
// "Aes" is very short and not all the Common Client Libraries have namespaces.)

/** @ignore */
var Crypto = require('../../crypto.js'); /** @ignore */
var Blob = require('../../util/blob.js').Blob; /** @ignore */
var DecryptKey = require('../decrypt-key.js').DecryptKey; /** @ignore */
var EncryptKey = require('../encrypt-key.js').EncryptKey; /** @ignore */
var EncryptAlgorithmType = require('./encrypt-params.js').EncryptAlgorithmType; /** @ignore */
var UseSubtleCrypto = require('../../use-subtle-crypto-node.js').UseSubtleCrypto; /** @ignore */
var SyncPromise = require('../../util/sync-promise.js').SyncPromise;

/**
 * The AesAlgorithm class provides static methods to manipulate keys, encrypt
 * and decrypt using the AES symmetric key cipher.
 * @note This class is an experimental feature. The API may change.
 * @constructor
 */
var AesAlgorithm = function AesAlgorithm()
{
};

exports.AesAlgorithm = AesAlgorithm;

/**
 * Generate a new random decrypt key for AES based on the given params.
 * @param {AesKeyParams} params The key params with the key size (in bits).
 * @return {DecryptKey} The new decrypt key.
 */
AesAlgorithm.generateKey = function(params)
{
  // Convert the key bit size to bytes.
  var key = Crypto.randomBytes(params.getKeySize() / 8);

  var decryptKey = new DecryptKey(new Blob(key, false));
  return decryptKey;
};

/**
 * Derive a new encrypt key from the given decrypt key value.
 * @param {Blob} keyBits The key value of the decrypt key.
 * @return {EncryptKey} The new encrypt key.
 */
AesAlgorithm.deriveEncryptKey = function(keyBits)
{
  return new EncryptKey(keyBits);
};

/**
 * Decrypt the encryptedData using the keyBits according the encrypt params.
 * @param {Blob} keyBits The key value.
 * @param {Blob} encryptedData The data to decrypt.
 * @param {EncryptParams} params This decrypts according to
 * params.getAlgorithmType() and other params as needed such as
 * params.getInitialVector().
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the decrypted Blob.
 */
AesAlgorithm.decryptPromise = function(keyBits, encryptedData, params, useSync)
{
  if (UseSubtleCrypto() && !useSync &&
      // Crypto.subtle doesn't implement ECB.
      params.getAlgorithmType() != EncryptAlgorithmType.AesEcb) {
    if (params.getAlgorithmType() == EncryptAlgorithmType.AesCbc) {
      return crypto.subtle.importKey
        ("raw", keyBits.buf(), { name: "AES-CBC" }, false,
         ["encrypt", "decrypt"])
      .then(function(key) {
        return crypto.subtle.decrypt
          ({ name: "AES-CBC", iv: params.getInitialVector().buf() },
           key, encryptedData.buf());
      })
      .then(function(result) {
        return Promise.resolve(new Blob(new Uint8Array(result), false));
      });
    }
    else
      return Promise.reject(new Error("unsupported encryption mode"));
  }
  else {
    if (params.getAlgorithmType() == EncryptAlgorithmType.AesEcb) {
      try {
        // ECB ignores the initial vector.
        var cipher = Crypto.createDecipheriv
          (keyBits.size()  == 32 ? "aes-256-ecb" : "aes-128-ecb",
           keyBits.buf(), "");
        return SyncPromise.resolve(new Blob
          (Buffer.concat([cipher.update(encryptedData.buf()), cipher.final()]),
           false));
      } catch (err) {
        return SyncPromise.reject(err);
      }
    }
    else if (params.getAlgorithmType() == EncryptAlgorithmType.AesCbc) {
      try {
        var cipher = Crypto.createDecipheriv
          (keyBits.size()  == 32 ? "aes-256-cbc" : "aes-128-cbc",
           keyBits.buf(), params.getInitialVector().buf());
        return SyncPromise.resolve(new Blob
          (Buffer.concat([cipher.update(encryptedData.buf()), cipher.final()]),
           false));
      } catch (err) {
        return SyncPromise.reject(err);
      }
    }
    else
      return SyncPromise.reject(new Error("unsupported encryption mode"));
  }
};

/**
 * Decrypt the encryptedData using the keyBits according the encrypt params.
 * @param {Blob} keyBits The key value.
 * @param {Blob} encryptedData The data to decrypt.
 * @param {EncryptParams} params This decrypts according to
 * params.getAlgorithmType() and other params as needed such as
 * params.getInitialVector().
 * @return {Blob} The decrypted data.
 * @throws Error If decryptPromise doesn't return a SyncPromise which is
 * already fulfilled.
 */
AesAlgorithm.decrypt = function(keyBits, encryptedData, params)
{
  return SyncPromise.getValue(this.decryptPromise
    (keyBits, encryptedData, params, true));
};

/**
 * Encrypt the plainData using the keyBits according the encrypt params.
 * @param {Blob} keyBits The key value.
 * @param {Blob} plainData The data to encrypt.
 * @param {EncryptParams} params This encrypts according to
 * params.getAlgorithmType() and other params as needed such as
 * params.getInitialVector().
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the encrypted Blob.
 */
AesAlgorithm.encryptPromise = function(keyBits, plainData, params, useSync)
{
  if (params.getAlgorithmType() == EncryptAlgorithmType.AesCbc) {
    if (params.getInitialVector().size() != AesAlgorithm.BLOCK_SIZE)
      return SyncPromise.reject(new Error("incorrect initial vector size"));
  }

  if (UseSubtleCrypto() && !useSync &&
      // Crypto.subtle doesn't implement ECB.
      params.getAlgorithmType() != EncryptAlgorithmType.AesEcb) {
    if (params.getAlgorithmType() == EncryptAlgorithmType.AesCbc) {
      return crypto.subtle.importKey
        ("raw", keyBits.buf(), { name: "AES-CBC" }, false,
         ["encrypt", "decrypt"])
      .then(function(key) {
        return crypto.subtle.encrypt
          ({ name: "AES-CBC", iv: params.getInitialVector().buf() },
           key, plainData.buf());
      })
      .then(function(result) {
        return Promise.resolve(new Blob(new Uint8Array(result), false));
      });
    }
    else
      return Promise.reject(new Error("unsupported encryption mode"));
  }
  else {
    if (params.getAlgorithmType() == EncryptAlgorithmType.AesEcb) {
      // ECB ignores the initial vector.
      var cipher = Crypto.createCipheriv
        (keyBits.size()  == 32 ? "aes-256-ecb" : "aes-128-ecb", keyBits.buf(), "");
      return SyncPromise.resolve(new Blob
        (Buffer.concat([cipher.update(plainData.buf()), cipher.final()]),
         false));
    }
    else if (params.getAlgorithmType() == EncryptAlgorithmType.AesCbc) {
      var cipher = Crypto.createCipheriv
        (keyBits.size()  == 32 ? "aes-256-cbc" : "aes-128-cbc",
         keyBits.buf(), params.getInitialVector().buf());
      return SyncPromise.resolve(new Blob
        (Buffer.concat([cipher.update(plainData.buf()), cipher.final()]),
         false));
    }
    else
      return SyncPromise.reject(new Error("unsupported encryption mode"));
  }
};

/**
 * Encrypt the plainData using the keyBits according the encrypt params.
 * @param {Blob} keyBits The key value.
 * @param {Blob} plainData The data to encrypt.
 * @param {EncryptParams} params This encrypts according to
 * params.getAlgorithmType() and other params as needed such as
 * params.getInitialVector().
 * @return {Blob} The encrypted data.
 * @throws Error If encryptPromise doesn't return a SyncPromise which is
 * already fulfilled.
 */
AesAlgorithm.encrypt = function(keyBits, plainData, params)
{
  return SyncPromise.getValue(this.encryptPromise
    (keyBits, plainData, params, true));
};

AesAlgorithm.BLOCK_SIZE = 16;
