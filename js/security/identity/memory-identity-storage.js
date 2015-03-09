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

var Data = require('../../data.js').Data;
var Name = require('../../name.js').Name;
var Blob = require('../../util/blob.js').Blob;
var KeyType = require('../security-types.js').KeyType;
var DataUtils = require('../../encoding/data-utils.js').DataUtils;
var SecurityException = require('../security-exception.js').SecurityException;
var IdentityStorage = require('./identity-storage.js').IdentityStorage;

/**
 * MemoryIdentityStorage extends IdentityStorage and implements its methods to
 * store identity, public key and certificate objects in memory. The application
 * must get the objects through its own means and add the objects to the
 * MemoryIdentityStorage object. To use permanent file-based storage, see
 * BasicIdentityStorage.
 * @constructor
 */
var MemoryIdentityStorage = function MemoryIdentityStorage()
{
  // Call the base constructor.
  IdentityStorage.call(this);

  // A list of name URI.
  this.identityStore = [];
  // The default identity in identityStore_, or "" if not defined.
  this.defaultIdentity = "";
  // The key is the keyName.toUri(). The value is the object
  //  {keyType, // number from KeyType
  //   keyDer   // Blob
  //  }.
  this.keyStore = {};
  // The key is the key is the certificateName.toUri(). The value is the
  //   encoded certificate.
  this.certificateStore = {};
};

MemoryIdentityStorage.prototype = new IdentityStorage();
MemoryIdentityStorage.prototype.name = "MemoryIdentityStorage";

exports.MemoryIdentityStorage = MemoryIdentityStorage;
/**
 * Check if the specified identity already exists.
 * @param {Name} identityName The identity name.
 * @returns {boolean} true if the identity exists, otherwise false.
 */
MemoryIdentityStorage.prototype.doesIdentityExist = function(identityName)
{
  return this.identityStore.indexOf(identityName.toUri()) !== -1;
};

/**
 * Add a new identity. Do nothing if the identity already exists.
 * @param {Name} identityName The identity name to be added.
 */
MemoryIdentityStorage.prototype.addIdentity = function(identityName)
{
  var identityUri = identityName.toUri();
  if (this.identityStore.indexOf(identityUri) >= 0)
    return;

  this.identityStore.push(identityUri);
};

/**
 * Revoke the identity.
 * @returns {boolean} true if the identity was revoked, false if not.
 */
MemoryIdentityStorage.prototype.revokeIdentity = function()
{
  throw new Error("MemoryIdentityStorage.revokeIdentity is not implemented");
};

/**
 * Check if the specified key already exists.
 * @param {Name} keyName The name of the key.
 * @returns {boolean} true if the key exists, otherwise false.
 */
MemoryIdentityStorage.prototype.doesKeyExist = function(keyName)
{
  return this.keyStore[keyName.toUri()] !== undefined;
};

/**
 * Add a public key to the identity storage. Also call addIdentity to ensure
 * that the identityName for the key exists.
 * @param {Name} keyName The name of the public key to be added.
 * @param {number} keyType Type of the public key to be added from KeyType, such
 * as KeyType.RSA..
 * @param {Blob} publicKeyDer A blob of the public key DER to be added.
 */
MemoryIdentityStorage.prototype.addKey = function(keyName, keyType, publicKeyDer)
{
  var identityName = keyName.getSubName(0, keyName.size() - 1);

  this.addIdentity(identityName);

  if (this.doesKeyExist(keyName))
    throw new SecurityException(new Error
      ("A key with the same name already exists!"));

  this.keyStore[keyName.toUri()] =
    { keyType: keyType, keyDer: new Blob(publicKeyDer) };
};

/**
 * Get the public key DER blob from the identity storage.
 * @param {Name} keyName The name of the requested public key.
 * @returns {Blob} The DER Blob.  If not found, return a Blob with a null pointer.
 */
MemoryIdentityStorage.prototype.getKey = function(keyName)
{
  var keyNameUri = keyName.toUri();
  var entry = this.keyStore[keyNameUri];
  if (entry === undefined)
    // Not found.  Silently return a null Blob.
    return new Blob();

  return entry.keyDer;
};

/**
 * Activate a key.  If a key is marked as inactive, its private part will not be
 * used in packet signing.
 * @param {Name} keyName name of the key
 */
MemoryIdentityStorage.prototype.activateKey = function(keyName)
{
  throw new Error("MemoryIdentityStorage.activateKey is not implemented");
};

/**
 * Deactivate a key. If a key is marked as inactive, its private part will not
 * be used in packet signing.
 * @param {Name} keyName name of the key
 */
MemoryIdentityStorage.prototype.deactivateKey = function(keyName)
{
  throw new Error("MemoryIdentityStorage.deactivateKey is not implemented");
};

/**
 * Check if the specified certificate already exists.
 * @param {Name} certificateName The name of the certificate.
 * @returns {boolean} true if the certificate exists, otherwise false.
 */
MemoryIdentityStorage.prototype.doesCertificateExist = function(certificateName)
{
  return this.certificateStore[certificateName.toUri()] !== undefined;
};

/**
 * Add a certificate to the identity storage.
 * @param {IdentityCertificate} certificate The certificate to be added.  This
 * makes a copy of the certificate.
 */
MemoryIdentityStorage.prototype.addCertificate = function(certificate)
{
  var certificateName = certificate.getName();
  var keyName = certificate.getPublicKeyName();

  if (!this.doesKeyExist(keyName))
    throw new SecurityException(new Error
      ("No corresponding Key record for certificate! " +
       keyName.toUri() + " " + certificateName.toUri()));

  // Check if the certificate already exists.
  if (this.doesCertificateExist(certificateName))
    throw new SecurityException(new Error
      ("Certificate has already been installed!"));

  // Check if the public key of the certificate is the same as the key record.
  var keyBlob = this.getKey(keyName);
  if (keyBlob.isNull() ||
      !DataUtils.arraysEqual(keyBlob.buf(),
        certificate.getPublicKeyInfo().getKeyDer().buf()))
    throw new SecurityException(new Error
      ("The certificate does not match the public key!"));

  // Insert the certificate.
  // wireEncode returns the cached encoding if available.
  this.certificateStore[certificateName.toUri()] = certificate.wireEncode();
};

/**
 * Get a certificate from the identity storage.
 * @param {Name} certificateName The name of the requested certificate.
 * @param {boolean} allowAny (optional) If false, only a valid certificate will
 * be returned, otherwise validity is disregarded. If omitted, allowAny is false.
 * @returns {IdentityCertificate} The requested certificate.  If not found, return null.
 */
MemoryIdentityStorage.prototype.getCertificate = function(certificateName, allowAny)
{
  var certificateNameUri = certificateName.toUri();
  if (this.certificateStore[certificateNameUri] === undefined)
    // Not found.  Silently return null.
    return null;

  var certificiate = new IdentityCertificate();
  certificiate.wireDecode(this.certificateStore[certificateNameUri]);
  return certificiate;
};

/*****************************************
 *           Get/Set Default             *
 *****************************************/

/**
 * Get the default identity.
 * @returns {Name} The name of default identity.
 * @throws SecurityException if the default identity is not set.
 */
MemoryIdentityStorage.prototype.getDefaultIdentity = function()
{
  if (this.defaultIdentity.length === 0)
    throw new SecurityException(new Error
      ("MemoryIdentityStorage.getDefaultIdentity: The default identity is not defined"));

  return new Name(this.defaultIdentity);
};

/**
 * Get the default key name for the specified identity.
 * @param {Name} identityName The identity name.
 * @returns {Name} The default key name.
 * @throws SecurityException if the default key name for the identity is not set.
 */
MemoryIdentityStorage.prototype.getDefaultKeyNameForIdentity = function
  (identityName)
{
  throw new Error("MemoryIdentityStorage.getDefaultKeyNameForIdentity is not implemented");
};

/**
 * Get the default certificate name for the specified key.
 * @param {Name} keyName The key name.
 * @returns {Name} The default certificate name.
 * @throws SecurityException if the default certificate name for the key name
 * is not set.
 */
MemoryIdentityStorage.prototype.getDefaultCertificateNameForKey = function(keyName)
{
  throw new Error("MemoryIdentityStorage.getDefaultCertificateNameForKey is not implemented");
};

/**
 * Set the default identity.  If the identityName does not exist, then clear the
 * default identity so that getDefaultIdentity() throws an exception.
 * @param {Name} identityName The default identity name.
 */
MemoryIdentityStorage.prototype.setDefaultIdentity = function(identityName)
{
  if (this.doesIdentityExist(identityName))
    this.defaultIdentity = identityName.toUri();
  else
    // The identity doesn't exist, so clear the default.
    this.defaultIdentity = "";
};

/**
 * Set the default key name for the specified identity.
 * @param {Name} keyName The key name.
 * @param {Name} identityNameCheck (optional) The identity name to check the
 * keyName.
 */
MemoryIdentityStorage.prototype.setDefaultKeyNameForIdentity = function
  (keyName, identityNameCheck)
{
  throw new Error("MemoryIdentityStorage.setDefaultKeyNameForIdentity is not implemented");
};

/**
 * Set the default key name for the specified identity.
 * @param {Name} keyName The key name.
 * @param {Name} certificateName The certificate name.
 */
MemoryIdentityStorage.prototype.setDefaultCertificateNameForKey = function
  (keyName, certificateName)
{
  throw new Error("MemoryIdentityStorage.setDefaultCertificateNameForKey is not implemented");
};

/*****************************************
 *            Delete Methods             *
 *****************************************/

/**
 * Delete a certificate.
 * @param {Name} certificateName The certificate name.
 */
MemoryIdentityStorage.prototype.deleteCertificateInfo = function(certificateName)
{
  throw new Error("MemoryIdentityStorage.deleteCertificateInfo is not implemented");
};

/**
 * Delete a public key and related certificates.
 * @param {Name} keyName The key name.
 */
MemoryIdentityStorage.prototype.deletePublicKeyInfo = function(keyName)
{
  throw new Error("MemoryIdentityStorage.deletePublicKeyInfo is not implemented");
};

/**
 * Delete an identity and related public keys and certificates.
 * @param {Name} identity The identity name.
 */
MemoryIdentityStorage.prototype.deleteIdentityInfo = function(identity)
{
  throw new Error("MemoryIdentityStorage.deleteIdentityInfo is not implemented");
};
