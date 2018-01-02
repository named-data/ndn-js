/**
 * Copyright (C) 2014-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx security by Yingdi Yu <yingdi@cs.ucla.edu>.
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
var Name = require('../../name.js').Name; /** @ignore */
var SecurityException = require('../security-exception.js').SecurityException; /** @ignore */
var SyncPromise = require('../../util/sync-promise.js').SyncPromise;

/**
 * IdentityStorage is a base class for the storage of identity, public keys and
 * certificates. Private keys are stored in PrivateKeyStorage.
 * This is an abstract base class.  A subclass must implement the methods.
 * @constructor
 */
var IdentityStorage = function IdentityStorage()
{
};

exports.IdentityStorage = IdentityStorage;

/**
 * Check if the specified identity already exists.
 * @param {Name} identityName The identity name.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns true if the identity
 * exists.
 */
IdentityStorage.prototype.doesIdentityExistPromise = function
  (identityName, useSync)
{
  return SyncPromise.reject(new Error
    ("IdentityStorage.doesIdentityExistPromise is not implemented"));
};

/**
 * Check if the specified identity already exists.
 * @param {Name} identityName The identity name.
 * @return {boolean} true if the identity exists, otherwise false.
 * @throws Error If doesIdentityExistPromise doesn't return a SyncPromise which
 * is already fulfilled.
 */
IdentityStorage.prototype.doesIdentityExist = function(identityName)
{
  return SyncPromise.getValue(this.doesIdentityExistPromise(identityName, true));
};

/**
 * Add a new identity. Do nothing if the identity already exists.
 * @param {Name} identityName The identity name to be added.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when the identity is
 * added.
 */
IdentityStorage.prototype.addIdentityPromise = function(identityName, useSync)
{
  return SyncPromise.reject(new Error
    ("IdentityStorage.addIdentityPromise is not implemented"));
};

/**
 * Add a new identity. Do nothing if the identity already exists.
 * @param {Name} identityName The identity name to be added.
 * @throws Error If addIdentityPromise doesn't return a SyncPromise which
 * is already fulfilled.
 */
IdentityStorage.prototype.addIdentity = function(identityName)
{
  return SyncPromise.getValue(this.addIdentityPromise(identityName, true));
};

/**
 * Revoke the identity.
 * @return {boolean} true if the identity was revoked, false if not.
 */
IdentityStorage.prototype.revokeIdentity = function()
{
  return SyncPromise.reject(new Error
    ("IdentityStorage.revokeIdentity is not implemented"));
};

/**
 * Generate a name for a new key belonging to the identity.
 * @param {Name} identityName The identity name.
 * @param {boolean} useKsk If true, generate a KSK name, otherwise a DSK name.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that returns the generated key Name.
 */
IdentityStorage.prototype.getNewKeyNamePromise = function
  (identityName, useKsk, useSync)
{
  var timestamp = Math.floor(new Date().getTime() / 1000.0);
  while (timestamp <= IdentityStorage.lastTimestamp)
    // Make the timestamp unique.
    timestamp += 1;
  IdentityStorage.lastTimestamp = timestamp;

  // Get the number of seconds as a string.
  var seconds = "" + timestamp;

  var keyIdStr;
  if (useKsk)
    keyIdStr = "ksk-" + seconds;
  else
    keyIdStr = "dsk-" + seconds;

  var keyName = new Name(identityName).append(keyIdStr);

  return this.doesKeyExistPromise(keyName, useSync)
  .then(function(exists) {
    if (exists)
      throw new SecurityException(new Error("Key name already exists"));

    return SyncPromise.resolve(keyName);
  });
};

/**
 * Generate a name for a new key belonging to the identity.
 * @param {Name} identityName The identity name.
 * @param {boolean} useKsk If true, generate a KSK name, otherwise a DSK name.
 * @return {Name} The generated key name.
 * @throws Error If getNewKeyNamePromise doesn't return a SyncPromise which
 * is already fulfilled.
 */
IdentityStorage.prototype.getNewKeyName = function(identityName, useKsk)
{
  return SyncPromise.getValue
    (this.getNewKeyNamePromise(identityName, useKsk, true));
};

/**
 * Check if the specified key already exists.
 * @param {Name} keyName The name of the key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns true if the key exists.
 */
IdentityStorage.prototype.doesKeyExistPromise = function(keyName, useSync)
{
  return SyncPromise.reject(new Error
    ("IdentityStorage.doesKeyExistPromise is not implemented"));
};

/**
 * Check if the specified key already exists.
 * @param {Name} keyName The name of the key.
 * @return {boolean} true if the key exists, otherwise false.
 * @throws Error If doesKeyExistPromise doesn't return a SyncPromise which
 * is already fulfilled.
 */
IdentityStorage.prototype.doesKeyExist = function(keyName)
{
  return SyncPromise.getValue(this.doesKeyExistPromise(keyName, true));
};

/**
 * Add a public key to the identity storage. Also call addIdentity to ensure
 * that the identityName for the key exists. However, if the key already
 * exists, do nothing.
 * @param {Name} keyName The name of the public key to be added.
 * @param {number} keyType Type of the public key to be added from KeyType, such
 * as KeyType.RSA..
 * @param {Blob} publicKeyDer A blob of the public key DER to be added.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when complete.
 */
IdentityStorage.prototype.addKeyPromise = function
  (keyName, keyType, publicKeyDer, useSync)
{
  return SyncPromise.reject(new Error
    ("IdentityStorage.addKeyPromise is not implemented"));
};

/**
 * Add a public key to the identity storage. Also call addIdentity to ensure
 * that the identityName for the key exists.
 * @param {Name} keyName The name of the public key to be added.
 * @param {number} keyType Type of the public key to be added from KeyType, such
 * as KeyType.RSA..
 * @param {Blob} publicKeyDer A blob of the public key DER to be added.
 * @throws SecurityException if a key with the keyName already exists.
 * @throws Error If addKeyPromise doesn't return a SyncPromise which
 * is already fulfilled.
 */
IdentityStorage.prototype.addKey = function(keyName, keyType, publicKeyDer)
{
  return SyncPromise.getValue
    (this.addKeyPromise(keyName, keyType, publicKeyDer, true));
};

/**
 * Get the public key DER blob from the identity storage.
 * @param {Name} keyName The name of the requested public key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the DER Blob, or a
 * promise rejected with SecurityException if the key doesn't exist.
 */
IdentityStorage.prototype.getKeyPromise = function(keyName, useSync)
{
  return SyncPromise.reject(new Error
    ("IdentityStorage.getKeyPromise is not implemented"));
};

/**
 * Get the public key DER blob from the identity storage.
 * @param {Name} keyName The name of the requested public key.
 * @return {Blob} The DER Blob.
 * @throws SecurityException if the key doesn't exist.
 * @throws Error If getKeyPromise doesn't return a SyncPromise which
 * is already fulfilled.
 */
IdentityStorage.prototype.getKey = function(keyName)
{
  return SyncPromise.getValue(this.getKeyPromise(keyName, true));
};

/**
 * Activate a key.  If a key is marked as inactive, its private part will not be
 * used in packet signing.
 * @param {Name} keyName name of the key
 */
IdentityStorage.prototype.activateKey = function(keyName)
{
  throw new Error("IdentityStorage.activateKey is not implemented");
};

/**
 * Deactivate a key. If a key is marked as inactive, its private part will not
 * be used in packet signing.
 * @param {Name} keyName name of the key
 */
IdentityStorage.prototype.deactivateKey = function(keyName)
{
  throw new Error("IdentityStorage.deactivateKey is not implemented");
};

/**
 * Check if the specified certificate already exists.
 * @param {Name} certificateName The name of the certificate.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns true if the certificate
 * exists.
 */
IdentityStorage.prototype.doesCertificateExistPromise = function
  (certificateName, useSync)
{
  return SyncPromise.reject(new Error
    ("IdentityStorage.doesCertificateExistPromise is not implemented"));
};

/**
 * Check if the specified certificate already exists.
 * @param {Name} certificateName The name of the certificate.
 * @return {boolean} true if the certificate exists, otherwise false.
 * @throws Error If doesCertificateExistPromise doesn't return a SyncPromise
 * which is already fulfilled.
 */
IdentityStorage.prototype.doesCertificateExist = function(certificateName)
{
  return SyncPromise.getValue
    (this.doesCertificateExistPromise(certificateName, true));
};

/**
 * Add a certificate to the identity storage. Also call addKey to ensure that
 * the certificate key exists. If the certificate is already installed, don't
 * replace it.
 * @param {IdentityCertificate} certificate The certificate to be added.  This
 * makes a copy of the certificate.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when finished.
 */
IdentityStorage.prototype.addCertificatePromise = function(certificate, useSync)
{
  return SyncPromise.reject(new Error
    ("IdentityStorage.addCertificatePromise is not implemented"));
};

/**
 * Add a certificate to the identity storage.
 * @param {IdentityCertificate} certificate The certificate to be added.  This
 * makes a copy of the certificate.
 * @throws SecurityException if the certificate is already installed.
 * @throws Error If addCertificatePromise doesn't return a SyncPromise which
 * is already fulfilled.
 */
IdentityStorage.prototype.addCertificate = function(certificate)
{
  return SyncPromise.getValue(this.addCertificatePromise(certificate, true));
};

/**
 * Get a certificate from the identity storage.
 * @param {Name} certificateName The name of the requested certificate.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the requested
 * IdentityCertificate, or a promise rejected with SecurityException if the
 * certificate doesn't exist.
 */
IdentityStorage.prototype.getCertificatePromise = function
  (certificateName, useSync)
{
  return SyncPromise.reject(new Error
    ("IdentityStorage.getCertificatePromise is not implemented"));
};

/**
 * Get a certificate from the identity storage.
 * @param {Name} certificateName The name of the requested certificate.
 * @return {IdentityCertificate} The requested certificate.
 * @throws SecurityException if the certificate doesn't exist.
 * @throws Error If getCertificatePromise doesn't return a SyncPromise which
 * is already fulfilled.
 */
IdentityStorage.prototype.getCertificate = function(certificateName)
{
  return SyncPromise.getValue(this.getValuePromise(certificateName, true));
};

/**
 * Get the TPM locator associated with this storage.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise|SyncPromise} A promise which returns the TPM locator, or a
 * promise rejected with SecurityException if the TPM locator doesn't exist.
 */
IdentityStorage.prototype.getTpmLocatorPromise = function(useSync)
{
  return SyncPromise.reject(new Error
    ("IdentityStorage.getTpmLocatorPromise is not implemented"));
};

/**
 * Get the TPM locator associated with this storage.
 * @return {string} The TPM locator.
 * @throws SecurityException if the TPM locator doesn't exist.
 * @throws Error If getTpmLocatorPromise doesn't return a SyncPromise which is
 * already fulfilled.
 */
IdentityStorage.prototype.getTpmLocator = function()
{
  return SyncPromise.getValue(this.getTpmLocatorPromise(true));
};

/*****************************************
 *           Get/Set Default             *
 *****************************************/

/**
 * Get the default identity.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the Name of default
 * identity, or a promise rejected with SecurityException if the default
 * identity is not set.
 */
IdentityStorage.prototype.getDefaultIdentityPromise = function(useSync)
{
  return SyncPromise.reject(new Error
    ("IdentityStorage.getDefaultIdentityPromise is not implemented"));
};

/**
 * Get the default identity.
 * @return {Name} The name of default identity.
 * @throws SecurityException if the default identity is not set.
 * @throws Error If getDefaultIdentityPromise doesn't return a SyncPromise
 * which is already fulfilled.
 */
IdentityStorage.prototype.getDefaultIdentity = function()
{
  return SyncPromise.getValue
    (this.getDefaultIdentityPromise(true));
};

/**
 * Get the default key name for the specified identity.
 * @param {Name} identityName The identity name.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the default key Name,
 * or a promise rejected with SecurityException if the default key name for the
 * identity is not set.
 */
IdentityStorage.prototype.getDefaultKeyNameForIdentityPromise = function
  (identityName, useSync)
{
  return SyncPromise.reject(new Error
    ("IdentityStorage.getDefaultKeyNameForIdentityPromise is not implemented"));
};

/**
 * Get the default key name for the specified identity.
 * @param {Name} identityName The identity name.
 * @return {Name} The default key name.
 * @throws SecurityException if the default key name for the identity is not set.
 * @throws Error If getDefaultKeyNameForIdentityPromise doesn't return a
 * SyncPromise which is already fulfilled.
 */
IdentityStorage.prototype.getDefaultKeyNameForIdentity = function(identityName)
{
  return SyncPromise.getValue
    (this.getDefaultKeyNameForIdentityPromise(identityName, true));
};

/**
 * Get the default certificate name for the specified identity.
 * @param {Name} identityName The identity name.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the default certificate
 * Name, or a promise rejected with SecurityException if the default key name
 * for the identity is not set or the default certificate name for the key name
 * is not set.
 */
IdentityStorage.prototype.getDefaultCertificateNameForIdentityPromise = function
  (identityName, useSync)
{
  var thisStorage = this;
  return this.getDefaultKeyNameForIdentityPromise(identityName)
  .then(function(keyName) {
    return thisStorage.getDefaultCertificateNameForKeyPromise(keyName);
  });
};

/**
 * Get the default certificate name for the specified identity.
 * @param {Name} identityName The identity name.
 * @return {Name} The default certificate name.
 * @throws SecurityException if the default key name for the identity is not
 * set or the default certificate name for the key name is not set.
 * @throws Error If getDefaultCertificateNameForIdentityPromise doesn't return
 * a SyncPromise which is already fulfilled.
 */
IdentityStorage.prototype.getDefaultCertificateNameForIdentity = function
  (identityName)
{
  return SyncPromise.getValue
    (this.getDefaultCertificateNameForIdentityPromise(identityName, true));
};

/**
 * Get the default certificate name for the specified key.
 * @param {Name} keyName The key name.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the default certificate
 * Name, or a promise rejected with SecurityException if the default certificate
 * name for the key name is not set.
 */
IdentityStorage.prototype.getDefaultCertificateNameForKeyPromise = function
  (keyName, useSync)
{
  return SyncPromise.reject(new Error
    ("IdentityStorage.getDefaultCertificateNameForKeyPromise is not implemented"));
};

/**
 * Get the default certificate name for the specified key.
 * @param {Name} keyName The key name.
 * @return {Name} The default certificate name.
 * @throws SecurityException if the default certificate name for the key name
 * is not set.
 * @throws Error If getDefaultCertificateNameForKeyPromise doesn't return a
 * SyncPromise which is already fulfilled.
 */
IdentityStorage.prototype.getDefaultCertificateNameForKey = function(keyName)
{
  return SyncPromise.getValue
    (this.getDefaultCertificateNameForKeyPromise(keyName, true));
};

/**
 * Append all the identity names to the nameList.
 * @param {Array<Name>} nameList Append result names to nameList.
 * @param {boolean} isDefault If true, add only the default identity name. If
 * false, add only the non-default identity names.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which fulfills when the names are added to
 * nameList.
 */
IdentityStorage.prototype.getAllIdentitiesPromise = function
  (nameList, isDefault, useSync)
{
  return SyncPromise.reject(new Error
    ("IdentityStorage.getAllIdentitiesPromise is not implemented"));
};

/**
 * Append all the key names of a particular identity to the nameList.
 * @param {Name} identityName The identity name to search for.
 * @param {Array<Name>} nameList Append result names to nameList.
 * @param {boolean} isDefault If true, add only the default key name. If false,
 * add only the non-default key names.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when the names are
 * added to nameList.
 */
IdentityStorage.prototype.getAllKeyNamesOfIdentityPromise = function
  (identityName, nameList, isDefault, useSync)
{
  return SyncPromise.reject(new Error
    ("IdentityStorage.getAllKeyNamesOfIdentityPromise is not implemented"));
};

/**
 * Append all the certificate names of a particular key name to the nameList.
 * @param {Name} keyName The key name to search for.
 * @param {Array<Name>} nameList Append result names to nameList.
 * @param {boolean} isDefault If true, add only the default certificate name.
 * If false, add only the non-default certificate names.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise which fulfills when the names are added to
 * nameList.
 */
IdentityStorage.prototype.getAllCertificateNamesOfKeyPromise = function
  (keyName, nameList, isDefault, useSync)
{
  return SyncPromise.reject(new Error
    ("IdentityStorage.getAllCertificateNamesOfKeyPromise is not implemented"));
};

/**
 * Append all the key names of a particular identity to the nameList.
 * @param {Name} identityName The identity name to search for.
 * @param {Array<Name>} nameList Append result names to nameList.
 * @param {boolean} isDefault If true, add only the default key name. If false,
 * add only the non-default key names.
 * @throws Error If getAllKeyNamesOfIdentityPromise doesn't return a
 * SyncPromise which is already fulfilled.
 */
IdentityStorage.prototype.getAllKeyNamesOfIdentity = function
  (identityName, nameList, isDefault)
{
  return SyncPromise.getValue
    (this.getAllKeyNamesOfIdentityPromise(identityName, nameList, isDefault, true));
};

/**
 * Set the default identity.  If the identityName does not exist, then clear the
 * default identity so that getDefaultIdentity() throws an exception.
 * @param {Name} identityName The default identity name.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when the default
 * identity is set.
 */
IdentityStorage.prototype.setDefaultIdentityPromise = function
  (identityName, useSync)
{
  return SyncPromise.reject(new Error
    ("IdentityStorage.setDefaultIdentityPromise is not implemented"));
};

/**
 * Set the default identity.  If the identityName does not exist, then clear the
 * default identity so that getDefaultIdentity() throws an exception.
 * @param {Name} identityName The default identity name.
 * @throws Error If setDefaultIdentityPromise doesn't return a SyncPromise which
 * is already fulfilled.
 */
IdentityStorage.prototype.setDefaultIdentity = function(identityName)
{
  return SyncPromise.getValue
    (this.setDefaultIdentityPromise(identityName, true));
};

/**
 * Set a key as the default key of an identity. The identity name is inferred
 * from keyName.
 * @param {Name} keyName The name of the key.
 * @param {Name} identityNameCheck (optional) The identity name to check that the
 * keyName contains the same identity name. If an empty name, it is ignored.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when the default key
 * name is set.
 */
IdentityStorage.prototype.setDefaultKeyNameForIdentityPromise = function
  (keyName, identityNameCheck, useSync)
{
  return SyncPromise.reject(new Error
    ("IdentityStorage.setDefaultKeyNameForIdentityPromise is not implemented"));
};

/**
 * Set a key as the default key of an identity. The identity name is inferred
 * from keyName.
 * @param {Name} keyName The name of the key.
 * @param {Name} identityNameCheck (optional) The identity name to check that the
 * keyName contains the same identity name. If an empty name, it is ignored.
 * @throws Error If setDefaultKeyNameForIdentityPromise doesn't return a
 * SyncPromise which is already fulfilled.
 */
IdentityStorage.prototype.setDefaultKeyNameForIdentity = function
  (keyName, identityNameCheck)
{
  return SyncPromise.getValue
    (this.setDefaultKeyNameForIdentityPromise(keyName, identityNameCheck, true));
};

/**
 * Set the default key name for the specified identity.
 * @param {Name} keyName The key name.
 * @param {Name} certificateName The certificate name.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when the default
 * certificate name is set.
 */
IdentityStorage.prototype.setDefaultCertificateNameForKeyPromise = function
  (keyName, certificateName, useSync)
{
  return SyncPromise.reject(new Error
    ("IdentityStorage.setDefaultCertificateNameForKeyPromise is not implemented"));
};

/**
 * Set the default key name for the specified identity.
 * @param {Name} keyName The key name.
 * @param {Name} certificateName The certificate name.
 * @throws Error If setDefaultCertificateNameForKeyPromise doesn't return a
 * SyncPromise which is already fulfilled.
 */
IdentityStorage.prototype.setDefaultCertificateNameForKey = function
  (keyName, certificateName)
{
  return SyncPromise.getValue
    (this.setDefaultCertificateNameForKeyPromise(keyName, certificateName, true));
};

/**
 * Get the certificate of the default identity.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the requested
 * IdentityCertificate or null if not found.
 */
IdentityStorage.prototype.getDefaultCertificatePromise = function(useSync)
{
  var thisStorage = this;
  return this.getDefaultIdentityPromise(useSync)
  .then(function(identityName) {
    return thisStorage.getDefaultCertificateNameForIdentityPromise
      (identityName, useSync);
  }, function(ex) {
    // The default is not defined.
    return SyncPromise.resolve(null);
  })
  .then(function(certName) {
    if (certName == null)
      return SyncPromise.resolve(null);

    return thisStorage.getCertificatePromise(certName, useSync);
  });
};

/**
 * Get the certificate of the default identity.
 * @return {IdentityCertificate} The requested certificate.  If not found,
 * return null.
 * @throws Error If getDefaultCertificatePromise doesn't return a SyncPromise
 * which is already fulfilled.
 */
IdentityStorage.prototype.getDefaultCertificate = function()
{
  return SyncPromise.getValue
    (this.getDefaultCertificatePromise(true));
};

/*****************************************
 *            Delete Methods             *
 *****************************************/

/**
 * Delete a certificate.
 * @param {Name} certificateName The certificate name.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when the certificate
 * info is deleted.
 */
IdentityStorage.prototype.deleteCertificateInfoPromise = function
  (certificateName, useSync)
{
  return SyncPromise.reject(new Error
    ("IdentityStorage.deleteCertificateInfoPromise is not implemented"));
};

/**
 * Delete a certificate.
 * @param {Name} certificateName The certificate name.
 * @throws Error If deleteCertificateInfoPromise doesn't return a SyncPromise
 * which is already fulfilled.
 */
IdentityStorage.prototype.deleteCertificateInfo = function(certificateName)
{
  return SyncPromise.getValue
    (this.deleteCertificateInfoPromise(certificateName, true));
};

/**
 * Delete a public key and related certificates.
 * @param {Name} keyName The key name.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when the public key
 * info is deleted.
 */
IdentityStorage.prototype.deletePublicKeyInfoPromise = function(keyName, useSync)
{
  return SyncPromise.reject
    (new Error("IdentityStorage.deletePublicKeyInfoPromise is not implemented"));
};

/**
 * Delete a public key and related certificates.
 * @param {Name} keyName The key name.
 * @throws Error If deletePublicKeyInfoPromise doesn't return a SyncPromise
 * which is already fulfilled.
 */
IdentityStorage.prototype.deletePublicKeyInfo = function(keyName)
{
  return SyncPromise.getValue
    (this.deletePublicKeyInfoPromise(keyName, true));
};

/**
 * Delete an identity and related public keys and certificates.
 * @param {Name} identityName The identity name.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when the identity info
 * is deleted.
 */
IdentityStorage.prototype.deleteIdentityInfoPromise = function
  (identityName, useSync)
{
  return SyncPromise.reject(new Error
    ("IdentityStorage.deleteIdentityInfoPromise is not implemented"));
};

/**
 * Delete an identity and related public keys and certificates.
 * @param {Name} identityName The identity name.
 * @throws Error If deleteIdentityInfoPromise doesn't return a SyncPromise
 * which is already fulfilled.
 */
IdentityStorage.prototype.deleteIdentityInfo = function(identityName)
{
  return SyncPromise.getValue
    (this.deleteIdentityInfoPromise(identityName, true));
};

// Track the lastTimestamp so that each timestamp is unique.
IdentityStorage.lastTimestamp = Math.floor(new Date().getTime() / 1000.0);
