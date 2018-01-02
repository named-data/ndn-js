/**
 * Copyright (C) 2015-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
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

// Use capitalized Crypto to not clash with the browser's crypto.subtle.
var Crypto = require('../../crypto.js');
// Don't require other modules since this is meant for the browser, not Node.js.

/**
 * IndexedDbPrivateKeyStorage extends PrivateKeyStorage to implement private key
 * storage using the browser's IndexedDB service.
 * @constructor
 */
var IndexedDbPrivateKeyStorage = function IndexedDbPrivateKeyStorage()
{
  PrivateKeyStorage.call(this);

  this.database = new Dexie("ndnsec-tpm");
  this.database.version(1).stores({
    // "nameHash" is transformName(keyName) // string
    // "encoding" is the public key DER     // Uint8Array
    publicKey: "nameHash",

    // "nameHash" is transformName(keyName)     // string
    // "encoding" is the PKCS 8 private key DER // Uint8Array
    privateKey: "nameHash"
  });
  this.database.open();
};

IndexedDbPrivateKeyStorage.prototype = new PrivateKeyStorage();
IndexedDbPrivateKeyStorage.prototype.name = "IndexedDbPrivateKeyStorage";

/**
 * Generate a pair of asymmetric keys.
 * @param {Name} keyName The name of the key pair.
 * @param {KeyParams} params The parameters of the key.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise that fulfills when the pair is generated.
 */
IndexedDbPrivateKeyStorage.prototype.generateKeyPairPromise = function
  (keyName, params, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("IndexedDbPrivateKeyStorage.generateKeyPairPromise is only supported for async")));

  var thisStorage = this;

  return thisStorage.doesKeyExistPromise(keyName, KeyClass.PUBLIC)
  .then(function(exists) {
    if (exists)
      throw new Error("Public key already exists");

    return thisStorage.doesKeyExistPromise(keyName, KeyClass.PRIVATE);
  })
  .then(function(exists) {
    if (exists)
      throw new Error("Private key already exists");

    if (params.getKeyType() === KeyType.RSA) {
      var privateKey = null;
      var publicKeyDer = null;

      return crypto.subtle.generateKey
        ({ name: "RSASSA-PKCS1-v1_5", modulusLength: params.getKeySize(),
           publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
           hash: {name: "SHA-256"} },
         true, ["sign", "verify"])
      .then(function(key) {
        privateKey = key.privateKey;

        // Export the public key to DER.
        return crypto.subtle.exportKey("spki", key.publicKey);
      })
      .then(function(exportedPublicKey) {
        publicKeyDer = new Uint8Array(exportedPublicKey);

        // Export the private key to DER.
        return crypto.subtle.exportKey("pkcs8", privateKey);
      })
      .then(function(pkcs8Der) {
        // Save the key pair
        return thisStorage.database.transaction
          ("rw", thisStorage.database.privateKey, thisStorage.database.publicKey, function () {
            thisStorage.database.publicKey.put
              ({nameHash: IndexedDbPrivateKeyStorage.transformName(keyName),
                encoding: publicKeyDer});
            thisStorage.database.privateKey.put
              ({nameHash: IndexedDbPrivateKeyStorage.transformName(keyName),
                encoding: new Uint8Array(pkcs8Der)});
          });
      });
    }
    else
      throw new Error("Only RSA key generation currently supported");
  });
};


/**
 * Delete a pair of asymmetric keys. If the key doesn't exist, do nothing.
 * @param {Name} keyName The name of the key pair.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise that fulfills when the key pair is deleted.
 */
IndexedDbPrivateKeyStorage.prototype.deleteKeyPairPromise = function
  (keyName, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("IndexedDbPrivateKeyStorage.deleteKeyPairPromise is only supported for async")));

  var thisStorage = this;
  // delete does nothing if the key doesn't exist.
  return this.database.publicKey.delete
    (IndexedDbPrivateKeyStorage.transformName(keyName))
  .then(function() {
    return thisStorage.database.privateKey.delete
      (IndexedDbPrivateKeyStorage.transformName(keyName));
  });
};

/**
 * Get the public key
 * @param {Name} keyName The name of public key.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise that returns the PublicKey.
 */
IndexedDbPrivateKeyStorage.prototype.getPublicKeyPromise = function
  (keyName, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("IndexedDbPrivateKeyStorage.getPublicKeyPromise is only supported for async")));

  return this.database.publicKey.get
    (IndexedDbPrivateKeyStorage.transformName(keyName))
  .then(function(publicKeyEntry) {
    return Promise.resolve(new PublicKey(new Blob(publicKeyEntry.encoding)));
  });
};

/**
 * Fetch the private key for keyName and sign the data to produce a signature Blob.
 * @param {Buffer} data Pointer to the input byte array.
 * @param {Name} keyName The name of the signing key.
 * @param {number} digestAlgorithm (optional) The digest algorithm from
 * DigestAlgorithm, such as DigestAlgorithm.SHA256. If omitted, use
 * DigestAlgorithm.SHA256.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise that returns the signature Blob.
 */
IndexedDbPrivateKeyStorage.prototype.signPromise = function
  (data, keyName, digestAlgorithm, useSync)
{
  useSync = (typeof digestAlgorithm === "boolean") ? digestAlgorithm : useSync;
  digestAlgorithm = (typeof digestAlgorithm === "boolean" || !digestAlgorithm) ? DigestAlgorithm.SHA256 : digestAlgorithm;

  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("IndexedDbPrivateKeyStorage.signPromise is only supported for async")));

  if (digestAlgorithm != DigestAlgorithm.SHA256)
    return Promise.reject(new SecurityException(new Error
      ("IndexedDbPrivateKeyStorage.sign: Unsupported digest algorithm")));

  // TODO: Support non-RSA keys.
  var algo = { name: "RSASSA-PKCS1-v1_5", hash: {name: "SHA-256" }};

  // Find the private key.
  return this.database.privateKey.get
    (IndexedDbPrivateKeyStorage.transformName(keyName))
  .then(function(privateKeyEntry) {
    return crypto.subtle.importKey
      ("pkcs8", new Blob(privateKeyEntry.encoding).buf(), algo, true, ["sign"]);
  })
  .then(function(privateKey) {
    return crypto.subtle.sign(algo, privateKey, data);
  })
  .then(function(signature) {
    return Promise.resolve(new Blob(new Uint8Array(signature), true));
  });
};

/**
 * Check if a particular key exists.
 * @param {Name} keyName The name of the key.
 * @param {number} keyClass The class of the key, e.g. KeyClass.PUBLIC,
 * KeyClass.PRIVATE, or KeyClass.SYMMETRIC.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which returns true if the key exists.
 */
IndexedDbPrivateKeyStorage.prototype.doesKeyExistPromise = function
  (keyName, keyClass, useSync)
{
  if (useSync)
    return Promise.reject(new SecurityException(new Error
      ("IndexedDbPrivateKeyStorage.doesKeyExistPromise is only supported for async")));

  var table = null;
  if (keyClass == KeyClass.PUBLIC)
    table = this.database.publicKey;
  else if (keyClass == KeyClass.PRIVATE)
    table = this.database.privateKey;
  else
    // Silently say that anything else doesn't exist.
    return Promise.resolve(false);

  return table.where("nameHash").equals
    (IndexedDbPrivateKeyStorage.transformName(keyName))
  .count()
  .then(function(count) {
    return Promise.resolve(count > 0);
  });
};

/**
 * Transform the key name into the base64 encoding of the hash (the same as in
 * FilePrivateKeyStorage without the file name extension).
 */
IndexedDbPrivateKeyStorage.transformName = function(keyName)
{
  var hash = Crypto.createHash('sha256');
  hash.update(new Buffer(keyName.toUri()));
  var fileName = hash.digest('base64');
  return fileName.replace(/\//g, '%');
};
