/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/tpm/back-end-mem.cpp
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
var SyncPromise = require('../../util/sync-promise.js').SyncPromise; /** @ignore */
var TpmPrivateKey = require('./tpm-private-key.js').TpmPrivateKey; /** @ignore */
var TpmKeyHandleMemory = require('./tpm-key-handle-memory.js').TpmKeyHandleMemory; /** @ignore */
var TpmBackEnd = require('./tpm-back-end.js').TpmBackEnd;

/**
 * TpmBackEndMemory extends TpmBackEnd to implement a TPM back-end using
 * in-memory storage.
 * @constructor
 */
var TpmBackEndMemory = function TpmBackEndMemory()
{
  // Call the base constructor.
  TpmBackEnd.call(this);

  // keyName URI string => TpmPrivateKey.
  // (Use a string because we can't use the Name object as the key in JavaScript.)
  this.keys_ = {};
};

TpmBackEndMemory.prototype = new TpmBackEnd();
TpmBackEndMemory.prototype.name = "TpmBackEndMemory";

exports.TpmBackEndMemory = TpmBackEndMemory;

TpmBackEndMemory.getScheme = function() { return "tpm-memory"; };

/**
 * A protected method to check if the key with name keyName exists in the TPM.
 * @param {Name} keyName The name of the key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns true if the key exists.
 */
TpmBackEndMemory.prototype.doHasKeyPromise_ = function(keyName, useSync)
{
  return SyncPromise.resolve(keyName.toUri() in this.keys_);
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
TpmBackEndMemory.prototype.doGetKeyHandlePromise_ = function(keyName, useSync)
{
  var key = this.keys_[keyName.toUri()];
  if (key == undefined)
    return SyncPromise.resolve(null);

  return SyncPromise.resolve(new TpmKeyHandleMemory(key));
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
TpmBackEndMemory.prototype.doCreateKeyPromise_ = function
  (identityName, params, useSync)
{
  var thisTpm = this;

  return TpmPrivateKey.generatePrivateKeyPromise(params, useSync)
  .then(function(key) {
    var keyHandle = new TpmKeyHandleMemory(key);

    TpmBackEnd.setKeyName(keyHandle, identityName, params);

    thisTpm.keys_[keyHandle.getKeyName().toUri()] = key;
    return SyncPromise.resolve(keyHandle);
  }, function(err) {
    return SyncPromise.reject(new TpmBackEnd.Error(new Error
      ("Error in TpmPrivateKey.generatePrivateKey: " + err)));
  });
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
TpmBackEndMemory.prototype.doDeleteKeyPromise_ = function(keyName, useSync)
{
  delete this.keys_[keyName.toUri()];
  return SyncPromise.resolve();
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
TpmBackEndMemory.prototype.doImportKeyPromise_ = function
  (keyName, pkcs8, password, useSync)
{
  if (password != null)
    return SyncPromise.reject(new TpmBackEnd.Error(new Error
      ("Private key password-encryption is not implemented")));

  try {
    var key = new TpmPrivateKey();
    key.loadPkcs8(pkcs8);
    this.keys_[keyName.toUri()] = key;
    return SyncPromise.resolve();
  } catch (ex) {
    return SyncPromise.reject(new TpmBackEnd.Error(new Error
      ("Cannot import private key: " + ex)));
  }
};
