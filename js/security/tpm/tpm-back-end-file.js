/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/tpm/back-end-file.hpp
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
var path = require('path'); /** @ignore */
var fs = require('fs'); /** @ignore */
var Crypto = require('../../crypto.js'); /** @ignore */
var Blob = require('../../util/blob.js').Blob; /** @ignore */
var TpmPrivateKey = require('./tpm-private-key.js').TpmPrivateKey; /** @ignore */
var TpmKeyHandleMemory = require('./tpm-key-handle-memory.js').TpmKeyHandleMemory; /** @ignore */
var TpmBackEnd = require('./tpm-back-end.js').TpmBackEnd; /** @ignore */
var SyncPromise = require('../../util/sync-promise.js').SyncPromise;

/**
 * TpmBackEndFile extends TpmBackEnd to implement a TPM back-end using on-disk
 * file storage. In this TPM, each private key is stored in a separate file with
 * permission 0400, i.e., owner read-only. The key is stored in PKCS #1 format
 * in base64 encoding.
 *
 * Create a TpmBackEndFile to use the given path to store files (of provided) or
 * to the default location.
 * @param {string} locationPath (optional) The full path of the directory to
 * store private keys. If omitted or null or "", use the default location
 * ~/.ndn/ndnsec-key-file.
 * @constructor
 */
var TpmBackEndFile = function TpmBackEndFile(locationPath)
{
  // Call the base constructor.
  TpmBackEnd.call(this);

  if (locationPath == undefined || locationPath == "") {
    var home = process.env.HOME || process.env.HOMEPATH || process.env.USERPROFILE;
    locationPath = path.join(home, ".ndn", "ndnsec-key-file");
  }

  this.keyStorePath_ = locationPath;
};

TpmBackEndFile.prototype = new TpmBackEnd();
TpmBackEndFile.prototype.name = "TpmBackEndFile";

exports.TpmBackEndFile = TpmBackEndFile;

/**
 * Create a TpmBackEndFile.Error which extends TpmBackEnd.Error and represents a
 * non-semantic error in backend TPM file processing.
 * Call with: throw new TpmBackEndFile.Error(new Error("message")).
 * @constructor
 * @param {Error} error The exception created with new Error.
 */
TpmBackEndFile.Error = function TpmBackEndFileError(error)
{
  // Call the base constructor.
  TpmBackEnd.Error.call(this, error);
}
TpmBackEndFile.Error.prototype = new TpmBackEnd.Error();
TpmBackEndFile.Error.prototype.name = "TpmBackEndFileError";

TpmBackEndFile.getScheme = function() { return "tpm-file"; };

/**
 * A protected method to check if the key with name keyName exists in the TPM.
 * @param {Name} keyName The name of the key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns true if the key exists.
 */
TpmBackEndFile.prototype.doHasKeyPromise_ = function(keyName, useSync)
{
  return Promise.resolve(this.hasKey_(keyName));
};

/**
 * Do the work of doHasKeyPromise_
 * @param {Name} keyName The name of the key.
 * @return {boolean} True if the key exists.
 */
TpmBackEndFile.prototype.hasKey_ = function(keyName)
{
  if (!fs.existsSync(this.toFilePath_(keyName)))
    return false;

  try {
    this.loadKey_(keyName);
    return true;
  } catch (ex) {
    return false;
  }
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
TpmBackEndFile.prototype.doGetKeyHandlePromise_ = function(keyName, useSync)
{
  if (!this.hasKey_(keyName))
    return null;

  return new TpmKeyHandleMemory(this.loadKey_(keyName));
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
TpmBackEndFile.prototype.doCreateKeyPromise_ = function
  (identityName, params, useSync)
{
  var key;
  try {
    // We know that TpmPrivateKey.generatePrivateKeyPromise is sync.
    key = SyncPromise.getValue(TpmPrivateKey.generatePrivateKeyPromise(params));
  } catch (ex) {
    return Promise.reject(new TpmBackEndFile.Error(new Error
      ("Error in TpmPrivateKey.generatePrivateKey: " + ex)));
  }
  var keyHandle = new TpmKeyHandleMemory(key);

  TpmBackEnd.setKeyName(keyHandle, identityName, params);

  try {
    this.saveKey_(keyHandle.getKeyName(), key);
  } catch (ex) {
    return Promise.reject(ex);
  }
  return Promise.resolve(keyHandle);
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
TpmBackEndFile.prototype.doDeleteKeyPromise_ = function(keyName, useSync)
{
  var filePath = this.toFilePath_(keyName);
  if (fs.existsSync(filePath)) {
    try {
      fs.unlinkSync(filePath);
    } catch (ex) {
      return Promise.reject(new TpmBackEndFile.Error(new Error
        ("Error deleting private key file: " + ex)));
    }
  }

  return Promise.resolve();
};

// TODO: doExportKeyPromise_
// TODO: doImportKeyPromise_

/**
 * Load the private key with name keyName from the key file directory.
 * @param {Name} keyName The name of the key.
 * @return {TpmPrivateKey} The key loaded into a TpmPrivateKey.
 */
TpmBackEndFile.prototype.loadKey_ = function(keyName)
{
  var key = new TpmPrivateKey();
  var pkcs;
  try {
    var base64Content = fs.readFileSync(this.toFilePath_(keyName)).toString();
    pkcs = new Buffer(base64Content, 'base64');
  } catch (ex) {
    throw new TpmBackEndFile.Error(new Error
      ("Error reading private key file: " + ex));
  }

  try {
    key.loadPkcs1(pkcs, null);
  } catch (ex) {
    throw new TpmBackEndFile.Error(new Error
      ("Error decoding private key file: " + ex));
  }

  return key;
};

/**
 * Save the private key using keyName into the key file directory.
 * @param {Name} keyName The name of the key.
 * @param {TpmPrivateKey} key The private key to save.
 */
TpmBackEndFile.prototype.saveKey_ = function(keyName, key)
{
  var filePath = this.toFilePath_(keyName);
  var base64;
  try {
    base64 = key.toPkcs1().buf().toString('base64');
  } catch (ex) {
    throw new TpmBackEndFile.Error(new Error
      ("Error encoding private key file: " + ex));
  }

  try {
    var options = { mode: parseInt('0400', 8) };
    fs.writeFileSync(filePath, base64, options);
  } catch (ex) {
    throw new TpmBackEndFile.Error(new Error
      ("Error writing private key file: " + ex));
  }
};

/**
 * Get the file path for the keyName, which is keyStorePath_ + "/" +
 * hex(sha256(keyName-wire-encoding)) + ".privkey" .
 * @param {Name} keyName The name of the key.
 * @return {string} The file path for the key.
 */
TpmBackEndFile.prototype.toFilePath_ = function(keyName)
{
  var keyEncoding = keyName.wireEncode();
  var hash = Crypto.createHash('sha256');
  hash.update(keyEncoding.buf());
  var digest = hash.digest();

  return path.join
    (this.keyStorePath_, new Blob(digest, false).toHex() + ".privkey");
};
