/**
 * Copyright (C) 2014-2015 Regents of the University of California.
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

var Name = require('../../name.js').Name;
var SecurityException = require('../security-exception.js').SecurityException;

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
 * @returns {boolean} true if the identity exists, otherwise false.
 */
IdentityStorage.prototype.doesIdentityExist = function(identityName)
{
  throw new Error("IdentityStorage.doesIdentityExist is not implemented");
};

/**
 * Add a new identity. Do nothing if the identity already exists.
 * @param {Name} identityName The identity name to be added.
 */
IdentityStorage.prototype.addIdentity = function(identityName)
{
  throw new Error("IdentityStorage.addIdentity is not implemented");
};

/**
 * Revoke the identity.
 * @returns {boolean} true if the identity was revoked, false if not.
 */
IdentityStorage.prototype.revokeIdentity = function()
{
  throw new Error("IdentityStorage.revokeIdentity is not implemented");
};

/**
 * Generate a name for a new key belonging to the identity.
 * @param {Name} identityName The identity name.
 * @param {boolean} useKsk If true, generate a KSK name, otherwise a DSK name.
 * @returns {Name} The generated key name.
 */
IdentityStorage.prototype.getNewKeyName = function(identityName, useKsk)
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
    keyIdStr = "KSK-" + seconds;
  else
    keyIdStr = "DSK-" + seconds;

  var keyName = new Name(identityName).append(keyIdStr);

  if (this.doesKeyExist(keyName))
    throw new SecurityException(new Error("Key name already exists"));

  return keyName;
};

/**
 * Check if the specified key already exists.
 * @param {Name} keyName The name of the key.
 * @returns {boolean} true if the key exists, otherwise false.
 */
IdentityStorage.prototype.doesKeyExist = function(keyName)
{
  throw new Error("IdentityStorage.doesKeyExist is not implemented");
};

/**
 * Add a public key to the identity storage. Also call addIdentity to ensure
 * that the identityName for the key exists.
 * @param {Name} keyName The name of the public key to be added.
 * @param {number} keyType Type of the public key to be added from KeyType, such
 * as KeyType.RSA..
 * @param {Blob} publicKeyDer A blob of the public key DER to be added.
 */
IdentityStorage.prototype.addKey = function(keyName, keyType, publicKeyDer)
{
  throw new Error("IdentityStorage.addKey is not implemented");
};

/**
 * Get the public key DER blob from the identity storage.
 * @param {Name} keyName The name of the requested public key.
 * @returns {Blob} The DER Blob.  If not found, return a Blob with a null pointer.
 */
IdentityStorage.prototype.getKey = function(keyName)
{
  throw new Error("IdentityStorage.getKey is not implemented");
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
 * @returns {boolean} true if the certificate exists, otherwise false.
 */
IdentityStorage.prototype.doesCertificateExist = function(certificateName)
{
  throw new Error("IdentityStorage.doesCertificateExist is not implemented");
};

/**
 * Add a certificate to the identity storage.
 * @param {IdentityCertificate} certificate The certificate to be added.  This
 * makes a copy of the certificate.
 */
IdentityStorage.prototype.addCertificate = function(certificate)
{
  throw new Error("IdentityStorage.addCertificate is not implemented");
};

/**
 * Get a certificate from the identity storage.
 * @param {Name} certificateName The name of the requested certificate.
 * @param {boolean} allowAny (optional) If false, only a valid certificate will
 * be returned, otherwise validity is disregarded. If omitted, allowAny is false.
 * @returns {IdentityCertificate} The requested certificate.  If not found, return a shared_ptr
 * with a null pointer.
 */
IdentityStorage.prototype.getCertificate = function(certificateName, allowAny)
{
  throw new Error("IdentityStorage.getCertificate is not implemented");
};

/*****************************************
 *           Get/Set Default             *
 *****************************************/

/**
 * Get the default identity.
 * @returns {Name} The name of default identity.
 * @throws SecurityException if the default identity is not set.
 */
IdentityStorage.prototype.getDefaultIdentity = function()
{
  throw new Error("IdentityStorage.getDefaultIdentity is not implemented");
};

/**
 * Get the default key name for the specified identity.
 * @param {Name} identityName The identity name.
 * @returns {Name} The default key name.
 * @throws SecurityException if the default key name for the identity is not set.
 */
IdentityStorage.prototype.getDefaultKeyNameForIdentity = function(identityName)
{
  throw new Error("IdentityStorage.getDefaultKeyNameForIdentity is not implemented");
};

/**
 * Get the default certificate name for the specified identity.
 * @param {Name} identityName The identity name.
 * @returns {Name} The default certificate name.
 * @throws SecurityException if the default key name for the identity is not
 * set or the default certificate name for the key name is not set.
 */
IdentityStorage.prototype.getDefaultCertificateNameForIdentity = function
  (identityName)
{
  var keyName = this.getDefaultKeyNameForIdentity(identityName);
  return this.getDefaultCertificateNameForKey(keyName);
};

/**
 * Get the default certificate name for the specified key.
 * @param {Name} keyName The key name.
 * @returns {Name} The default certificate name.
 * @throws SecurityException if the default certificate name for the key name
 * is not set.
 */
IdentityStorage.prototype.getDefaultCertificateNameForKey = function(keyName)
{
  throw new Error("IdentityStorage.getDefaultCertificateNameForKey is not implemented");
};

/**
 * Append all the key names of a particular identity to the nameList.
 * @param identityName {Name} The identity name to search for.
 * @param nameList {Array<Name>} Append result names to nameList.
 * @param isDefault {boolean} If true, add only the default key name. If false,
 * add only the non-default key names.
 */
IdentityStorage.prototype.getAllKeyNamesOfIdentity = function
  (identityName, nameList, isDefault)
{
  throw new Error("IdentityStorage.getAllKeyNamesOfIdentity is not implemented");
};

/**
 * Set the default identity.  If the identityName does not exist, then clear the
 * default identity so that getDefaultIdentity() throws an exception.
 * @param {Name} identityName The default identity name.
 */
IdentityStorage.prototype.setDefaultIdentity = function(identityName)
{
  throw new Error("IdentityStorage.setDefaultIdentity is not implemented");
};

/**
 * Set the default key name for the specified identity.
 * @param {Name} keyName The key name.
 * @param {Name} identityNameCheck (optional) The identity name to check the
 * keyName.
 */
IdentityStorage.prototype.setDefaultKeyNameForIdentity = function
  (keyName, identityNameCheck)
{
  throw new Error("IdentityStorage.setDefaultKeyNameForIdentity is not implemented");
};

/**
 * Set the default key name for the specified identity.
 * @param {Name} keyName The key name.
 * @param {Name} certificateName The certificate name.
 */
IdentityStorage.prototype.setDefaultCertificateNameForKey = function
  (keyName, certificateName)
{
  throw new Error("IdentityStorage.setDefaultCertificateNameForKey is not implemented");
};

/*****************************************
 *            Delete Methods             *
 *****************************************/

/**
 * Delete a certificate.
 * @param {Name} certificateName The certificate name.
 */
IdentityStorage.prototype.deleteCertificateInfo = function(certificateName)
{
  throw new Error("IdentityStorage.deleteCertificateInfo is not implemented");
};

/**
 * Delete a public key and related certificates.
 * @param {Name} keyName The key name.
 */
IdentityStorage.prototype.deletePublicKeyInfo = function(keyName)
{
  throw new Error("IdentityStorage.deletePublicKeyInfo is not implemented");
};

/**
 * Delete an identity and related public keys and certificates.
 * @param {Name} identity The identity name.
 */
IdentityStorage.prototype.deleteIdentityInfo = function(identity)
{
  throw new Error("IdentityStorage.deleteIdentityInfo is not implemented");
};

// Track the lastTimestamp so that each timestamp is unique.
IdentityStorage.lastTimestamp = Math.floor(new Date().getTime() / 1000.0);
