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
var Blob = require('../../util/blob.js').Blob; /** @ignore */
var SecurityException = require('../security-exception.js').SecurityException; /** @ignore */
var IdentityCertificate = require('../certificate/identity-certificate.js').IdentityCertificate; /** @ignore */
var SyncPromise = require('../../util/sync-promise.js').SyncPromise; /** @ignore */
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

  // The map key is the identityName.toUri(). The value is the object
  //   {defaultKey // Name
  //   }.
  this.identityStore = {};
  // The default identity in identityStore, or "" if not defined.
  this.defaultIdentity = "";
  // The key is the keyName.toUri(). The value is the object
  //  {keyType, // number from KeyType
  //   keyDer   // Blob
  //   defaultCertificate // Name
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
 * @return {SyncPromise} A promise which returns true if the identity exists.
 */
MemoryIdentityStorage.prototype.doesIdentityExistPromise = function(identityName)
{
  return SyncPromise.resolve
    (this.identityStore[identityName.toUri()] !== undefined);
};

/**
 * Add a new identity. Do nothing if the identity already exists.
 * @param {Name} identityName The identity name to be added.
 * @return {SyncPromise} A promise which fulfills when the identity is added.
 */
MemoryIdentityStorage.prototype.addIdentityPromise = function(identityName)
{
  var identityUri = identityName.toUri();
  if (this.identityStore[identityUri] === undefined)
    this.identityStore[identityUri] = { defaultKey: null };

  return SyncPromise.resolve();
};

/**
 * Check if the specified key already exists.
 * @param {Name} keyName The name of the key.
 * @return {SyncPromise} A promise which returns true if the key exists.
 */
MemoryIdentityStorage.prototype.doesKeyExistPromise = function(keyName)
{
  return SyncPromise.resolve(this.keyStore[keyName.toUri()] !== undefined);
};

/**
 * Add a public key to the identity storage. Also call addIdentity to ensure
 * that the identityName for the key exists. However, if the key already
 * exists, do nothing.
 * @param {Name} keyName The name of the public key to be added.
 * @param {number} keyType Type of the public key to be added from KeyType, such
 * as KeyType.RSA..
 * @param {Blob} publicKeyDer A blob of the public key DER to be added.
 * @return {SyncPromise} A promise which fulfills when complete.
 */
MemoryIdentityStorage.prototype.addKeyPromise = function
  (keyName, keyType, publicKeyDer)
{
  if (keyName.size() === 0)
    return SyncPromise.resolve();

  if (this.doesKeyExist(keyName))
    return SyncPromise.resolve();

  var identityName = keyName.getSubName(0, keyName.size() - 1);

  this.addIdentity(identityName);

  this.keyStore[keyName.toUri()] =
    { keyType: keyType, keyDer: new Blob(publicKeyDer), defaultCertificate: null };

  return SyncPromise.resolve();
};

/**
 * Get the public key DER blob from the identity storage.
 * @param {Name} keyName The name of the requested public key.
 * @return {SyncPromise} A promise which returns the DER Blob, or a promise
 * rejected with SecurityException if the key doesn't exist.
 */
MemoryIdentityStorage.prototype.getKeyPromise = function(keyName)
{
  if (keyName.size() === 0)
    return SyncPromise.reject(new SecurityException(new Error
      ("MemoryIdentityStorage.getKeyPromise: Empty keyName")));

  var keyNameUri = keyName.toUri();
  var entry = this.keyStore[keyNameUri];
  if (entry === undefined)
    return SyncPromise.reject(new SecurityException(new Error
      ("MemoryIdentityStorage.getKeyPromise: The key does not exist")));

  return SyncPromise.resolve(entry.keyDer);
};

/**
 * Check if the specified certificate already exists.
 * @param {Name} certificateName The name of the certificate.
 * @return {SyncPromise} A promise which returns true if the certificate exists.
 */
MemoryIdentityStorage.prototype.doesCertificateExistPromise = function
  (certificateName)
{
  return SyncPromise.resolve
    (this.certificateStore[certificateName.toUri()] !== undefined);
};

/**
 * Add a certificate to the identity storage. Also call addKey to ensure that
 * the certificate key exists. If the certificate is already installed, don't
 * replace it.
 * @param {IdentityCertificate} certificate The certificate to be added.  This
 * makes a copy of the certificate.
 * @return {SyncPromise} A promise which fulfills when finished.
 */
MemoryIdentityStorage.prototype.addCertificatePromise = function(certificate)
{
  var certificateName = certificate.getName();
  var keyName = certificate.getPublicKeyName();

  this.addKey(keyName, certificate.getPublicKeyInfo().getKeyType(),
         certificate.getPublicKeyInfo().getKeyDer());

  if (this.doesCertificateExist(certificateName))
    return SyncPromise.resolve();

  // Insert the certificate.
  // wireEncode returns the cached encoding if available.
  this.certificateStore[certificateName.toUri()] = certificate.wireEncode();

  return SyncPromise.resolve();
};

/**
 * Get a certificate from the identity storage.
 * @param {Name} certificateName The name of the requested certificate.
 * @return {SyncPromise} A promise which returns the requested
 * IdentityCertificate, or a promise rejected with SecurityException if the
 * certificate doesn't exist.
 */
MemoryIdentityStorage.prototype.getCertificatePromise = function
  (certificateName)
{
  var certificateNameUri = certificateName.toUri();
  if (this.certificateStore[certificateNameUri] === undefined)
    return SyncPromise.reject(new SecurityException(new Error
      ("MemoryIdentityStorage.getCertificatePromise: The certificate does not exist")));

  var certificate = new IdentityCertificate();
  try {
    certificate.wireDecode(this.certificateStore[certificateNameUri]);
  } catch (ex) {
    return SyncPromise.reject(new SecurityException(new Error
      ("MemoryIdentityStorage.getCertificatePromise: The certificate cannot be decoded")));
  }
  return SyncPromise.resolve(certificate);
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
  return SyncPromise.resolve("tpm-memory:");
};

/*****************************************
 *           Get/Set Default             *
 *****************************************/

/**
 * Get the default identity.
 * @return {SyncPromise} A promise which returns the Name of default identity,
 * or a promise rejected with SecurityException if the default identity is not
 * set.
 */
MemoryIdentityStorage.prototype.getDefaultIdentityPromise = function()
{
  if (this.defaultIdentity.length === 0)
    return SyncPromise.reject(new SecurityException(new Error
      ("MemoryIdentityStorage.getDefaultIdentity: The default identity is not defined")));

  return SyncPromise.resolve(new Name(this.defaultIdentity));
};

/**
 * Get the default key name for the specified identity.
 * @param {Name} identityName The identity name.
 * @return {SyncPromise} A promise which returns the default key Name, or a
 * promise rejected with SecurityException if the default key name for the
 * identity is not set.
 */
MemoryIdentityStorage.prototype.getDefaultKeyNameForIdentityPromise = function
  (identityName)
{
  var identityUri = identityName.toUri();
  if (this.identityStore[identityUri] !== undefined) {
    if (this.identityStore[identityUri].defaultKey != null)
      return SyncPromise.resolve(this.identityStore[identityUri].defaultKey);
    else
      return SyncPromise.reject(new SecurityException(new Error
        ("No default key set.")));
  }
  else
    return SyncPromise.reject(new SecurityException(new Error("Identity not found.")));
};

/**
 * Get the default certificate name for the specified key.
 * @param {Name} keyName The key name.
 * @return {SyncPromise} A promise which returns the default certificate Name,
 * or a promise rejected with SecurityException if the default certificate name
 * for the key name is not set.
 */
MemoryIdentityStorage.prototype.getDefaultCertificateNameForKeyPromise = function
  (keyName)
{
  var keyUri = keyName.toUri();
  if (this.keyStore[keyUri] !== undefined) {
    if (this.keyStore[keyUri].defaultCertificate != null)
      return SyncPromise.resolve(this.keyStore[keyUri].defaultCertificate);
    else
      return SyncPromise.reject(new SecurityException(new Error
        ("No default certificate set.")));
  }
  else
    return SyncPromise.reject(new SecurityException(new Error("Key not found.")));
};

/**
 * Set the default identity.  If the identityName does not exist, then clear the
 * default identity so that getDefaultIdentity() throws an exception.
 * @param {Name} identityName The default identity name.
 * @return {SyncPromise} A promise which fulfills when the default identity is set.
 */
MemoryIdentityStorage.prototype.setDefaultIdentityPromise = function
  (identityName)
{
  var identityUri = identityName.toUri();
  if (this.identityStore[identityUri] !== undefined)
    this.defaultIdentity = identityUri;
  else
    // The identity doesn't exist, so clear the default.
    this.defaultIdentity = "";

  return SyncPromise.resolve();
};

/**
 * Set a key as the default key of an identity. The identity name is inferred
 * from keyName.
 * @param {Name} keyName The name of the key.
 * @param {Name} identityNameCheck (optional) The identity name to check that the
 * keyName contains the same identity name. If an empty name, it is ignored.
 * @return {SyncPromise} A promise which fulfills when the default key name is
 * set.
 */
MemoryIdentityStorage.prototype.setDefaultKeyNameForIdentityPromise = function
  (keyName, identityNameCheck)
{
  identityNameCheck = (identityNameCheck instanceof Name) ? identityNameCheck : null;

  var identityName = keyName.getPrefix(-1);

  if (identityNameCheck != null && identityNameCheck.size() > 0 &&
      !identityNameCheck.equals(identityName))
    return SyncPromise.reject(new SecurityException(new Error
      ("The specified identity name does not match the key name")));

  var identityUri = identityName.toUri();
  if (this.identityStore[identityUri] !== undefined)
    this.identityStore[identityUri].defaultKey = new Name(keyName);

  return SyncPromise.resolve();
};

/**
 * Set the default key name for the specified identity.
 * @param {Name} keyName The key name.
 * @param {Name} certificateName The certificate name.
 * @return {SyncPromise} A promise which fulfills when the default certificate
 * name is set.
 */
MemoryIdentityStorage.prototype.setDefaultCertificateNameForKeyPromise = function
  (keyName, certificateName)
{
  var keyUri = keyName.toUri();
  if (this.keyStore[keyUri] !== undefined)
    this.keyStore[keyUri].defaultCertificate = new Name(certificateName);

  return SyncPromise.resolve();
};

/*****************************************
 *            Delete Methods             *
 *****************************************/

/**
 * Delete a certificate.
 * @param {Name} certificateName The certificate name.
 * @return {SyncPromise} A promise which fulfills when the certificate
 * info is deleted.
 */
MemoryIdentityStorage.prototype.deleteCertificateInfoPromise = function
  (certificateName)
{
  return SyncPromise.reject(new Error
    ("MemoryIdentityStorage.deleteCertificateInfoPromise is not implemented"));
};

/**
 * Delete a public key and related certificates.
 * @param {Name} keyName The key name.
 * @return {SyncPromise} A promise which fulfills when the public key info is
 * deleted.
 */
MemoryIdentityStorage.prototype.deletePublicKeyInfoPromise = function(keyName)
{
  return SyncPromise.reject(new Error
    ("MemoryIdentityStorage.deletePublicKeyInfoPromise is not implemented"));
};

/**
 * Delete an identity and related public keys and certificates.
 * @param {Name} identity The identity name.
 * @return {SyncPromise} A promise which fulfills when the identity info is
 * deleted.
 */
MemoryIdentityStorage.prototype.deleteIdentityInfoPromise = function(identity)
{
  return SyncPromise.reject(new Error
    ("MemoryIdentityStorage.deleteIdentityInfoPromise is not implemented"));
};
