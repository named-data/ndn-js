/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/tpm/back-end.cpp
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
var Crypto = require('../../crypto.js'); /** @ignore */
var Name = require('../../name.js').Name; /** @ignore */
var Blob = require('../../util/blob.js').Blob; /** @ignore */
var KeyIdType = require('../key-id-type.js').KeyIdType; /** @ignore */
var PibKey = require('../pib/pib-key.js').PibKey; /** @ignore */
var Tpm = require('./tpm.js').Tpm; /** @ignore */
var SyncPromise = require('../../util/sync-promise.js').SyncPromise;

/**
 * TpmBackEnd is an abstract base class for a TPM backend implementation which
 * provides a TpmKeyHandle to the TPM front end. This class defines the
 * interface that an actual TPM backend implementation should provide, for
 * example TpmBackEndMemory.
 * @constructor
 */
var TpmBackEnd = function TpmBackEnd()
{
};

exports.TpmBackEnd = TpmBackEnd;

/**
 * Create a TpmBackEnd.Error which represents a non-semantic error in backend
 * TPM processing.
 * Call with: throw new TpmBackEnd.Error(new Error("message")).
 * @constructor
 * @param {Error} error The exception created with new Error.
 */
TpmBackEnd.Error = function TpmBackEndError(error)
{
  if (error) {
    error.__proto__ = TpmBackEnd.Error.prototype;
    return error;
  }
};

TpmBackEnd.Error.prototype = new Error();
TpmBackEnd.Error.prototype.name = "TpmBackEndError";

/**
 * Check if the key with name keyName exists in the TPM.
 * @param {Name} keyName The name of the key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {SyncPromise} A promise which returns true if the key exists.
 */
TpmBackEnd.prototype.hasKeyPromise = function(keyName, useSync)
{
  return this.doHasKeyPromise_(keyName, useSync);
};

/**
 * Get the handle of the key with name keyName. Calling getKeyHandle multiple
 * times with the same keyName will return different TpmKeyHandle objects that
 * all refer to the same key.
 * @param {Name} keyName The name of the key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns a TpmKeyHandle of the
 * key, or returns null if the key does not exist.
 */
TpmBackEnd.prototype.getKeyHandlePromise = function(keyName, useSync)
{
  return this.doGetKeyHandlePromise_(keyName, useSync);
};

/**
 * Create a key for the identityName according to params.
 * @param {Name} identityName The name if the identity.
 * @param {KeyParams} params The KeyParams for creating the key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns a TpmKeyHandle of the
 * created key, or a promise rejected with TpmBackEnd.Error if the key cannot be
 * created.
 */
TpmBackEnd.prototype.createKeyPromise = function(identityName, params, useSync)
{
  var thisTpm = this;

  return SyncPromise.resolve()
  .then(function() {
    // Do key name checking.
    if (params.getKeyIdType() == KeyIdType.USER_SPECIFIED) {
      // The keyId is pre-set.
      var keyName = PibKey.constructKeyName(identityName, params.getKeyId());
      return thisTpm.hasKeyPromise(keyName, useSync)
      .then(function(hasKey) {
        if (hasKey)
          return SyncPromise.reject(new Tpm.Error(new Error
            ("Key `" + keyName.toUri() + "` already exists")));
        else
          return SyncPromise.resolve();
      });
    }
    else if (params.getKeyIdType() == KeyIdType.SHA256) {
      // The key name will be assigned in setKeyName after the key is generated.
      return SyncPromise.resolve();
    }
    else if (params.getKeyIdType() == KeyIdType.RANDOM) {
      var keyId;

      var loop = function() {
        var random = Crypto.randomBytes(8);
        keyId = new Name.Component(new Blob(random, false));
        var keyName = PibKey.constructKeyName(identityName, keyId);

        return thisTpm.hasKeyPromise(keyName, useSync)
        .then(function(hasKey) {
          if (!hasKey)
            // We got a unique one.
            return SyncPromise.resolve();
          else
            // Loop again.
            return loop();
        });
      }

      return loop()
      .then(function() {
        params.setKeyId(keyId);
        return SyncPromise.resolve();
      });
    }
    else
      return SyncPromise.reject(new Tpm.Error(new Error
        ("Unsupported key id type")));
  })
  .then(function() {
    return thisTpm.doCreateKeyPromise_(identityName, params, useSync);
  });
};

/**
 * Delete the key with name keyName. If the key doesn't exist, do nothing.
 * Note: Continuing to use existing Key handles on a deleted key results in
 * undefined behavior.
 * @param {Name} keyName The name of the key to delete.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when finished, or a
 * promise rejected with TpmBackEnd.Error if the deletion fails.
 */
TpmBackEnd.prototype.deleteKeyPromise = function(keyName, useSync)
{
  return this.doDeleteKeyPromise_(keyName, useSync);
};

// TODO: exportKey

/**
 * Import an encoded private key with name keyName in PKCS #8 format, possibly
 * password-encrypted.
 * @param {Name} keyName The name of the key to use in the TPM.
 * @param {Buffer} pkcs8 The input byte buffer. If the password is supplied,
 * this is a PKCS #8 EncryptedPrivateKeyInfo. If the password is none, this is
 * an unencrypted PKCS #8 PrivateKeyInfo.
 * @param {Buffer} password The password for decrypting the private key, which
 * should have characters in the range of 1 to 127. If the password is supplied,
 * use it to decrypt the PKCS #8 EncryptedPrivateKeyInfo. If the password is
 * null, import an unencrypted PKCS #8 PrivateKeyInfo.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when finished, or a
 * promise rejected with TpmBackEnd.Error for an error importing the key.
 */
TpmBackEnd.prototype.importKeyPromise = function(keyName, pkcs8, password, useSync)
{
  var thisTpm = this;

  return this.hasKeyPromise(keyName, useSync)
  .then(function(hasKey) {
    if (hasKey)
      return SyncPromise.reject(new TpmBackEnd.Error(new Error
        ("Key `" + keyName.toUri() + "` already exists")));
    else
      return thisTpm.doImportKeyPromise_(keyName, pkcs8, password, useSync);
  });
};

// TODO: isTerminalMode
// TODO: setTerminalMode
// TODO: isTpmLocked
// TODO: unlockTpm

/**
 * Set the key name in keyHandle according to identityName and params.
 * @param {TpmKeyHandle} keyHandle
 * @param {Name} identityName
 * @param {KeyParams} params
 */
TpmBackEnd.setKeyName = function(keyHandle, identityName, params)
{
  var keyId;

  if (params.getKeyIdType() == KeyIdType.USER_SPECIFIED)
    keyId = params.getKeyId();
  else if (params.getKeyIdType() == KeyIdType.SHA256) {
    var hash = Crypto.createHash('sha256');
    hash.update(keyHandle.derivePublicKey().buf());
    keyId = Name.Component(new Blob(hash.digest(), false));
  }
  else if (params.getKeyIdType() == KeyIdType.RANDOM) {
    if (params.getKeyId().getValue().size() == 0)
      throw new TpmBackEnd.Error(new Error
        ("setKeyName: The keyId is empty for type RANDOM"));
    keyId = params.getKeyId();
  }
  else
    throw new TpmBackEnd.Error(new Error
      ("setKeyName: unrecognized params.getKeyIdType()"));

  keyHandle.setKeyName(PibKey.constructKeyName(identityName, keyId));
};

/**
 * A protected method to check if the key with name keyName exists in the TPM.
 * @param {Name} keyName The name of the key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns true if the key exists.
 */
TpmBackEnd.prototype.doHasKeyPromise_ = function(keyName, useSync)
{
  return SyncPromise.reject(new Error
    ("TpmBackEnd.doHasKeyPromise_ is not implemented"));
};

/**
 * A protected method to get the handle of the key with name keyName.
 * @param {Name} keyName The name of the key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns a TpmKeyHandle of the
 * key, or returns null if the key does not exist.
 */
TpmBackEnd.prototype.doGetKeyHandlePromise_ = function(keyName, useSync)
{
  return SyncPromise.reject(new Error
    ("TpmBackEnd.doGetKeyHandlePromise_ is not implemented"));
};

/**
 * A protected method to create a key for identityName according to params. The
 * created key is named as: /<identityName>/[keyId]/KEY . The key name is set in
 * the returned TpmKeyHandle.
 * @param {Name} identityName The name if the identity.
 * @param {KeyParams} params The KeyParams for creating the key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the TpmKeyHandle of
 * the created key, or a promise rejected with TpmBackEnd.Error if the key
 * cannot be created.
 */
TpmBackEnd.prototype.doCreateKeyPromise_ = function(identityName, params, useSync)
{
  return SyncPromise.reject(new Error
    ("TpmBackEnd.doCreateKeyPromise_ is not implemented"));
};

/**
 * A protected method to delete the key with name keyName. If the key doesn't
 * exist, do nothing.
 * @param {Name} keyName The name of the key to delete.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when finished, or a
 * promise rejected with TpmBackEnd.Error if the deletion fails.
 */
TpmBackEnd.prototype.doDeleteKeyPromise_ = function(keyName, useSync)
{
  return SyncPromise.reject(new Error
    ("TpmBackEnd.doDeleteKeyPromise_ is not implemented"));
};

// TODO: doExportKeyPromise_

/**
 * A protected method to import an encoded private key with name keyName in
 * PKCS #8 format, possibly password-encrypted.
 * @param {Name} keyName The name of the key to use in the TPM.
 * @param {Buffer} pkcs8 The input byte buffer. If the password is supplied,
 * this is a PKCS #8 EncryptedPrivateKeyInfo. If the password is none, this is
 * an unencrypted PKCS #8 PrivateKeyInfo.
 * @param {Buffer} password The password for decrypting the private key, which
 * should have characters in the range of 1 to 127. If the password is supplied,
 * use it to decrypt the PKCS #8 EncryptedPrivateKeyInfo. If the password is
 * null, import an unencrypted PKCS #8 PrivateKeyInfo.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when finished, or a
 * promise rejected with TpmBackEnd.Error for an error importing the key.
 */
TpmBackEnd.prototype.doImportKeyPromise_ = function
  (keyName, pkcs8, password, useSync)
{
  return SyncPromise.reject(new Error
    ("TpmBackEnd.doImportKeyPromise_ is not implemented"));
};
