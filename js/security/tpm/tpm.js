/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/tpm/tpm.cpp
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

/** @ignore */
var KeyType = require('../security-types').KeyType; /** @ignore */
var SyncPromise = require('../../util/sync-promise.js').SyncPromise;

/**
 * The TPM (Trusted Platform Module) stores the private portion of a user's
 * cryptography keys. The format and location of stored information is indicated
 * by the TPM locator. The TPM is designed to work with a PIB (Public
 * Information Base) which stores public keys and related information such as
 * certificates.
 *
 * The TPM also provides functionalities of cryptographic transformation, such
 * as signing and decryption.
 *
 * A TPM consists of a unified front-end interface and a backend implementation.
 * The front-end caches the handles of private keys which are provided by the
 * backend implementation.
 *
 * Note: A Tpm instance is created and managed only by the KeyChain. It is
 * returned by the KeyChain getTpm() method, through which it is possible to
 * check for the existence of private keys, get public keys for the private
 * keys, sign, and decrypt the supplied buffers using managed private keys.
 *
 * Create a new TPM instance with the specified location. This constructor
 * should only be called by KeyChain.
 *
 * @param {string} scheme The scheme for the TPM.
 * @param {string} location The location for the TPM.
 * @param {TpmBackEnd} backEnd The TPM back-end implementation.
 * @constructor
 */
var Tpm = function Tpm(scheme, location, backEnd)
{
  // Name URI string => TpmKeyHandle
  // (Use a string because we can't use the Name object as the key in JavaScript.)
  this.keys_ = {};

  this.scheme_ = scheme;
  this.location_ = location;
  this.backEnd_ = backEnd;
};

exports.Tpm = Tpm;

/**
 * Create a Tpm.Error which which represents a semantic error in TPM processing.
 * Call with: throw new Tpm.Error(new Error("message")).
 * @constructor
 * @param {Error} error The exception created with new Error.
 */
Tpm.Error = function TpmError(error)
{
  if (error) {
    error.__proto__ = Tpm.Error.prototype;
    return error;
  }
};

Tpm.Error.prototype = new Error();
Tpm.Error.prototype.name = "TpmError";

Tpm.prototype.getTpmLocator = function()
{
  return this.scheme_ + ":" + this.location_;
};

/**
 * Check if the key with name keyName exists in the TPM.
 * @param {Name} keyName The name of the key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns true if the key exists.
 */
Tpm.prototype.hasKeyPromise = function(keyName, useSync)
{
  return this.backEnd_.hasKeyPromise(keyName, useSync);
};

/**
 * Get the public portion of an asymmetric key pair with name keyName.
 * @param {Name} keyName The name of the key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the encoded public key
 * Blob (or an isNull Blob if the key does not exist).
 */
Tpm.prototype.getPublicKeyPromise = function(keyName, useSync)
{
  return this.findKeyPromise_(keyName, useSync)
  .then(function(key) {
    if (key == null)
      return SyncPromise.resolve(new Blob());
    else
      return SyncPromise.resolve(key.derivePublicKey());
  });
};

/**
 * Compute a digital signature from the byte buffer using the key with name
 * keyName.
 * @param {Buffer} data The input byte buffer.
 * @param {Name} keyName The name of the key.
 * @param {number} digestAlgorithm The digest algorithm as an int from the
 * DigestAlgorithm enum.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the signature Blob (or
 * an isNull Blob if the key does not exist), or a promise rejected
 * with TpmBackEnd.Error for an error in signing.
 */
Tpm.prototype.signPromise = function(data, keyName, digestAlgorithm, useSync)
{
  return this.findKeyPromise_(keyName, useSync)
  .then(function(key) {
    if (key == null)
      return SyncPromise.resolve(new Blob());
    else
      return key.signPromise(digestAlgorithm, data, useSync);
  });
};

/**
 * Return the plain text which is decrypted from cipherText using the key with
 * name keyName.
 * @param {Buffer} cipherText The cipher text byte buffer.
 * @param {Name} keyName The name of the key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the decrypted data Blob
 * (or an isNull Blob if the key does not exist).
 */
Tpm.prototype.decryptPromise = function(cipherText, keyName, useSync)
{
  return this.findKeyPromise_(keyName, useSync)
  .then(function(key) {
    if (key == null)
      return SyncPromise.resolve(new Blob());
    else
      return key.decryptPromise(cipherText, useSync);
  });
};

// TODO: isTerminalModePromise
// TODO: setTerminalModePromise
// TODO: isTpmLockedPromise
// TODO: unlockTpmPromise

/**
 * Get the TpmBackEnd. This should only be called by KeyChain.
 * @return {TpmBackEnd}
 */
Tpm.prototype.getBackEnd_ = function() { return this.backEnd_; };

/**
 * Create a key for the identityName according to params. The created key is
 * named /<identityName>/[keyId]/KEY . This should only be called by KeyChain.
 * @param {Name} identityName The name if the identity.
 * @param {KeyParams} params The KeyParams for creating the key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the Name of the created
 * key, or a promise rejected with Tpm.Error if params is invalid or if the key
 * type is unsupported, or a promise rejected with TpmBackEnd.Error if the key
 * already exists or cannot be created.
 */
Tpm.prototype.createKeyPromise_ = function(identityName, params, useSync)
{
  if (params.getKeyType() == KeyType.RSA ||
      params.getKeyType() == KeyType.ECDSA) {
    var thisTpm = this;

    return this.backEnd_.createKeyPromise(identityName, params, useSync)
    .then(function(keyHandle) {
      var keyName = keyHandle.getKeyName()
      thisTpm.keys_[keyName.toUri()] = keyHandle;
      return SyncPromise.resolve(keyName);
    });
  }
  else
    return SyncPromise.resolve(new Tpm.Error(new Error
      ("createKey: Unsupported key type")));
};

/**
 * Delete the key with name keyName. If the key doesn't exist, do nothing.
 * Note: Continuing to use existing Key handles on a deleted key results in
 * undefined behavior. This should only be called by KeyChain.
 * @param {Name} keyName The name of the key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when finished, or a
 * promise rejected with TpmBackEnd.Error if the deletion fails.
 */
Tpm.prototype.deleteKeyPromise_ = function(keyName, useSync)
{
  delete this.keys_[keyName.toUri()];

  return this.backEnd_.deleteKeyPromise(keyName, useSync);
};

// TODO: exportPrivateKeyPromise_

/**
 * Import an encoded private key with name keyName in PKCS #8 format, possibly
 * password-encrypted. This should only be called by KeyChain.
 * @param {Name} keyName The name of the key to use in the TPM.
 * @param {Buffer} pkcs8 The input byte buffer. If the password is supplied,
 * this is a PKCS #8 EncryptedPrivateKeyInfo. If the password is none, this is
 * an unencrypted PKCS #8 PrivateKeyInfo.
 * @param {Buffer} password The password for decrypting the private key. If the
 * password is supplied, use it to decrypt the PKCS #8 EncryptedPrivateKeyInfo.
 * If the password is null, import an unencrypted PKCS #8 PrivateKeyInfo.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which return true for success, false 
 * if importing fails.
 */
Tpm.prototype.importPrivateKeyPromise_ = function(keyName, pkcs8, password, useSync)
{
  return this.backEnd_.importKeyPromise(keyName, pkcs8, password, useSync)
  .then(function() {
    return SyncPromise.resolve(true);
  }, function() {
    return SyncPromise.resolve(false);
  });
};

/**
 * Get the TpmKeyHandle with name keyName, using backEnd_.getKeyHandlePromise if
 * it is not already cached in keys_.
 * @param {Name} keyName The name of the key, which is copied.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which return the TpmKeyHandle in the
 * keys_ cache, or null if no key exists with name keyName.
 */
Tpm.prototype.findKeyPromise_ = function(keyName, useSync)
{
  var keyNameUri = keyName.toUri();
  var handle = this.keys_[keyNameUri];

  if (handle != undefined)
    return SyncPromise.resolve(handle);

  var thisTpm = this;
  return this.backEnd_.getKeyHandlePromise(keyName, useSync)
  .then(function(handle) {
    if (handle != null) {
      thisTpm.keys_[keyNameUri] = handle;
      return SyncPromise.resolve(handle);
    }

    return SyncPromise.resolve(null);
  });
};
