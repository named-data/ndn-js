/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/pib/pib-memory.cpp
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
var CertificateV2 = require('../v2/certificate-v2.js').CertificateV2; /** @ignore */
var Pib = require('./pib.js').Pib; /** @ignore */
var PibKey = require('./pib-key.js').PibKey; /** @ignore */
var SyncPromise = require('../../util/sync-promise.js').SyncPromise; /** @ignore */
var PibImpl = require('./pib-impl.js').PibImpl;

/**
 * PibMemory extends PibImpl and is used by the Pib class as an in-memory
 * implementation of a PIB. All the contents in the PIB are stored in memory and
 * have the same lifetime as the PibMemory instance.
 * @constructor
 */
var PibMemory = function PibMemory()
{
  // Call the base constructor.
  PibImpl.call(this);

  this.tpmLocator_ = "";

  this.defaultIdentityName_ = null;

  // Set of Name.
  this.identityNames_ = [];

  // identityName URI string => default key Name.
  // (Use a string because we can't use the Name object as the key in JavaScript.)
  this.defaultKeyNames_ = {};

  // keyName URI string => keyBits Blob.
  // (Use a string because we can't use the Name object as the key in JavaScript.)
  this.keys_ = {};

  // keyName URI string => default certificate Name.
  // (Use a string because we can't use the Name object as the key in JavaScript.)
  this.defaultCertificateNames_ = {};

  // certificateName URI string => CertificateV2.
  // (Use a string because we can't use the Name object as the key in JavaScript.)
  this.certificates_ = {};
};

PibMemory.prototype = new PibImpl();
PibMemory.prototype.name = "PibMemory";

exports.PibMemory = PibMemory;

PibMemory.getScheme = function() { return "pib-memory"; }

// TpmLocator management.

/**
 * Set the corresponding TPM information to tpmLocator. This method does not
 * reset the contents of the PIB.
 * @param {string} tpmLocator The TPM locator string.
 * @return {SyncPromise} A promise which fulfills when the TPM locator is set.
 */
PibMemory.prototype.setTpmLocatorPromise = function(tpmLocator)
{
  this.tpmLocator_ = tpmLocator;
  return SyncPromise.resolve();
};

/**
 * Get the TPM Locator.
 * @return {SyncPromise} A promise which returns the TPM locator string.
 */
PibMemory.prototype.getTpmLocatorPromise = function()
{
  return SyncPromise.resolve(this.tpmLocator_);
};

// Identity management.

/**
 * Check for the existence of an identity.
 * @param {Name} identityName The name of the identity.
 * @return {SyncPromise} A promise which returns true if the identity exists,
 * otherwise false.
 */
PibMemory.prototype.hasIdentityPromise = function(identityName)
{
  return SyncPromise.resolve(this.hasIdentity_(identityName));
};

/**
 * Do the work of hasIdentityPromise.
 */
PibMemory.prototype.hasIdentity_ = function(identityName)
{
  for (var i in this.identityNames_) {
    var name = this.identityNames_[i];
    if (name.equals(identityName))
      return true;
  }

  return false;
};

/**
 * Add the identity. If the identity already exists, do nothing. If no default
 * identity has been set, set the added identity as the default.
 * @param {Name} identityName The name of the identity to add. This copies the
 * name.
 * @return {SyncPromise} A promise which fulfills when the identity is added.
 */
PibMemory.prototype.addIdentityPromise = function(identityName)
{
  this.addIdentity_(identityName);
  return SyncPromise.resolve();
};

/**
 * Do the work of addIdentityPromise.
 */
PibMemory.prototype.addIdentity_ = function(identityName)
{
  var identityNameCopy = new Name(identityName);
  if (!this.hasIdentity_(identityNameCopy))
    this.identityNames_.push(identityNameCopy);

  if (this.defaultIdentityName_ === null)
    this.defaultIdentityName_ = identityNameCopy;
};

/**
 * Remove the identity and its related keys and certificates. If the default
 * identity is being removed, no default identity will be selected. If the
 * identity does not exist, do nothing.
 * @param {Name} identityName The name of the identity to remove.
 * @return {SyncPromise} A promise which fulfills when the identity is removed.
 */
PibMemory.prototype.removeIdentityPromise = function(identityName)
{
  // Go backwards through the list so we can remove entries.
  for (var i = this.identityNames_.length - 1; i >= 0; --i) {
    if (this.identityNames_[i].equals(identityName))
      this.identityNames_.splice(i, 1);
  }

  if (this.defaultIdentityName_ !== null &&
      identityName.equals(this.defaultIdentityName_))
    this.defaultIdentityName_ = null;

  var keyNames = this.getKeysOfIdentity_(identityName);
  for (var i in keyNames)
    this.removeKey_(keyNames[i]);

  return SyncPromise.resolve();
};

/**
 * Erase all certificates, keys, and identities.
 * @return {SyncPromise} A promise which fulfills when the identities are cleared.
 */
PibMemory.prototype.clearIdentitiesPromise = function()
{
  this.defaultIdentityName_ = null;
  this.identityNames_ = [];
  this.defaultKeyNames_ = {};
  this.keys_ = {};
  this.defaultCertificateNames_ = {};
  this.certificates_ = {};

  return SyncPromise.resolve();
};

/**
 * Get the names of all the identities.
 * @return {SyncPromise} A promise which returns a fresh set of identity names
 * as an array of Name. The Name objects are fresh copies.
 */
PibMemory.prototype.getIdentitiesPromise = function()
{
  // Copy the Name objects.
  var result = [];
  for (var i in this.identityNames_) {
    var name = this.identityNames_[i];
    result.push(new Name(name));
  }

  return SyncPromise.resolve(result);
};

/**
 * Set the identity with the identityName as the default identity. If the
 * identity with identityName does not exist, then it will be created.
 * @param {Name} identityName The name for the default identity. This copies the
 * name.
 * @return {SyncPromise} A promise which fulfills when the default identity is
 * set.
 */
PibMemory.prototype.setDefaultIdentityPromise = function(identityName)
{
  this.addIdentity_(identityName);
  // Copy the name.
  this.defaultIdentityName_ = new Name(identityName);

  return SyncPromise.resolve();
};

/**
 * Get the default identity.
 * @return {SyncPromise} A promise which returns the Name of the default
 * identity as a fresh copy, or a promise rejected with Pib.Error for no default
 * identity.
 */
PibMemory.prototype.getDefaultIdentityPromise = function()
{
  if (this.defaultIdentityName_ !== null)
    // Copy the name.
    return SyncPromise.resolve(new Name(this.defaultIdentityName_));

  return SyncPromise.reject(new Pib.Error(new Error("No default identity")));
};

// Key management.

/**
 * Check for the existence of a key with keyName.
 * @param {Name} keyName The name of the key.
 * @return {SyncPromise} A promise which returns true if the key exists,
 * otherwise false. Return false if the identity does not exist.
 */
PibMemory.prototype.hasKeyPromise = function(keyName)
{
  return SyncPromise.resolve(this.hasKey_(keyName));
};

/**
 * Do the work of hasKeyPromise.
 */
PibMemory.prototype.hasKey_ = function(keyName)
{
  return keyName.toUri() in this.keys_;
};

/**
 * Add the key. If a key with the same name already exists, overwrite the key.
 * If the identity does not exist, it will be created. If no default key for the
 * identity has been set, then set the added key as the default for the
 * identity. If no default identity has been set, identity becomes the default.
 * @param {Name} identityName The name of the identity that the key belongs to.
 * This copies the name.
 * @param {Name} keyName The name of the key. This copies the name.
 * @param {Buffer} key The public key bits. This copies the array.
 * @return {SyncPromise} A promise which fulfills when the key is added.
 */
PibMemory.prototype.addKeyPromise = function(identityName, keyName, key)
{
  this.addKey_(identityName, keyName, key);
  return SyncPromise.resolve();
};

/**
 * Do the work of addKeyPromise,
 */
PibMemory.prototype.addKey_ = function(identityName, keyName, key)
{
  this.addIdentity_(identityName);

  var keyNameCopy = new Name(keyName);
  this.keys_[keyNameCopy.toUri()] = new Blob(key, true);

  var identityNameUri = identityName.toUri();
  if (!(identityNameUri in this.defaultKeyNames_))
    this.defaultKeyNames_[identityNameUri] = keyNameCopy;
};

/**
 * Remove the key with keyName and its related certificates. If the key does not
 * exist, do nothing.
 * @param {Name} keyName The name of the key.
 * @return {SyncPromise} A promise which fulfills when the key is removed.
 */
PibMemory.prototype.removeKeyPromise = function(keyName)
{
  this.removeKey_(keyName);
  return SyncPromise.resolve();
};

/**
 * Do the work of removeKeyPromise.
 */
PibMemory.prototype.removeKey_ = function(keyName)
{
  var identityName = PibKey.extractIdentityFromKeyName(keyName);

  delete this.keys_[keyName.toUri()];
  delete this.defaultKeyNames_[identityName.toUri()];

  var certificateNames = this.getCertificatesOfKey_(keyName);
  for (var i in certificateNames)
    this.removeCertificate_(certificateNames[i]);
};

/**
 * Get the key bits of a key with name keyName.
 * @param {Name} keyName The name of the key.
 * @return {SyncPromise} A promise which returns the key bits as a Blob, or a
 * promise rejected with Pib.Error if the key does not exist.
 */
PibMemory.prototype.getKeyBitsPromise = function(keyName)
{
  if (!this.hasKey_(keyName))
    return SyncPromise.reject(new Pib.Error(new Error
      ("Key `" + keyName.toUri() + "` not found")));

  var key = this.keys_[keyName.toUri()];
  return SyncPromise.resolve(key);
};

/**
 * Get all the key names of the identity with the name identityName. The
 * returned key names can be used to create a KeyContainer. With a key name and
 * a backend implementation, one can create a Key front end instance.
 * @param {Name} identityName The name of the identity.
 * @return SyncPromise} A promise which returns the set of key names as an array
 * of Name. The Name objects are fresh copies. If the identity does not exist,
 * return an empty array.
 */
PibMemory.prototype.getKeysOfIdentityPromise = function(identityName)
{
  return SyncPromise.resolve(this.getKeysOfIdentity_(identityName));
};

/**
 * Do the work of getKeysOfIdentityPromise
 */
PibMemory.prototype.getKeysOfIdentity_ = function(identityName)
{
  var ids = [];
  for (var keyNameUri in this.keys_) {
    var keyName = new Name(keyNameUri);
    if (identityName.equals(PibKey.extractIdentityFromKeyName(keyName)))
      // keyName is already a copy created from the URI.
      ids.push(keyName);
  }

  return ids;
};

/**
 * Set the key with keyName as the default key for the identity with name
 * identityName.
 * @param {Name} identityName The name of the identity. This copies the name.
 * @param {Name} keyName The name of the key. This copies the name.
 * @return {SyncPromise} A promise which fulfills when the default key is set,
 * or a promise rejected with Pib.Error if the key does not exist.
 */
PibMemory.prototype.setDefaultKeyOfIdentityPromise = function
  (identityName, keyName)
{
  if (!this.hasKey_(keyName))
    return SyncPromise.reject(new Pib.Error(new Error
      ("Key `" + keyName.toUri() + "` not found")));

  // Copy the Name.
  this.defaultKeyNames_[identityName.toUri()] = new Name(keyName);
  return SyncPromise.resolve();
};

/**
 * Get the name of the default key for the identity with name identityName.
 * @param {Name} identityName The name of the identity.
 * @return {SyncPromise} A promise which returns the name of the default key as
 * a fresh copy, or a promise rejected with Pib.Error if the identity does not
 * exist.
 */
PibMemory.prototype.getDefaultKeyOfIdentityPromise = function(identityName)
{
  var defaultKey = this.defaultKeyNames_[identityName.toUri()];
  if (defaultKey == undefined)
    return SyncPromise.reject(new Pib.Error(new Error
      ("No default key for identity `" + identityName.toUri() + "`")));

  // Copy the name.
  return SyncPromise.resolve(new Name(defaultKey));
};

// Certificate management.

/**
 * Check for the existence of a certificate with name certificateName.
 * @param {Name} certificateName The name of the certificate.
 * @return {SyncPromise} A promise which returns true if the certificate exists,
 * otherwise false.
 */
PibMemory.prototype.hasCertificatePromise = function(certificateName)
{
  return SyncPromise.resolve(this.hasCertificate_(certificateName));
};

/**
 * Do the work of hasCertificatePromise.
 */
PibMemory.prototype.hasCertificate_ = function(certificateName)
{
  return certificateName.toUri() in this.certificates_;
};

/**
 * Add the certificate. If a certificate with the same name (without implicit
 * digest) already exists, then overwrite the certificate. If the key or
 * identity does not exist, they will be created. If no default certificate for
 * the key has been set, then set the added certificate as the default for the
 * key. If no default key was set for the identity, it will be set as the
 * default key for the identity. If no default identity was selected, the
 * certificate's identity becomes the default.
 * @param {CertificateV2} certificate The certificate to add. This copies the
 * object.
 * @return {SyncPromise} A promise which fulfills when the certificate is added.
 */
PibMemory.prototype.addCertificatePromise = function(certificate)
{
  var certificateNameCopy = new Name(certificate.getName());
  // getKeyName already makes a new Name.
  var keyNameCopy = certificate.getKeyName();
  var identity = certificate.getIdentity();

  this.addKey_(identity, keyNameCopy, certificate.getContent().buf());

  this.certificates_[certificateNameCopy.toUri()] =
    new CertificateV2(certificate);
  var keyNameUri = keyNameCopy.toUri();
  if (!(keyNameUri in this.defaultCertificateNames_))
    this.defaultCertificateNames_[keyNameUri] = certificateNameCopy;

  return SyncPromise.resolve();
};

/**
 * Remove the certificate with name certificateName. If the certificate does not
 * exist, do nothing.
 * @param {Name} certificateName The name of the certificate.
 * @return {SyncPromise} A promise which fulfills when the certificate is
 * removed.
 */
PibMemory.prototype.removeCertificatePromise = function(certificateName)
{
  this.removeCertificate_(certificateName);
  return SyncPromise.resolve();
};

/**
 * Do the work of removeCertificatePromise.
 */
PibMemory.prototype.removeCertificate_ = function(certificateName)
{
  delete this.certificates_[certificateName.toUri()];

  var keyName = CertificateV2.extractKeyNameFromCertName(certificateName);
  var keyNameUri = keyName.toUri();
  var defaultCertificateName = this.defaultCertificateNames_[keyNameUri];

  if (defaultCertificateName != undefined &&
      defaultCertificateName.equals(certificateName))
    delete this.defaultCertificateNames_[keyNameUri];
};

/**
 * Get the certificate with name certificateName.
 * @param {Name} certificateName The name of the certificate.
 * @return {SyncPromise} A promise which returns the CertificateV2, or a promise
 * rejected with Pib.Error if the certificate does not exist.
 */
PibMemory.prototype.getCertificatePromise = function(certificateName)
{
  if (!this.hasCertificate_(certificateName))
    return SyncPromise.reject(new Pib.Error(new Error
      ("Certificate `" + certificateName.toUri() +  "` does not exist")));

  return SyncPromise.resolve(new CertificateV2
    (this.certificates_[certificateName.toUri()]));
};

/**
 * Get a list of certificate names of the key with id keyName. The returned
 * certificate names can be used to create a PibCertificateContainer. With a
 * certificate name and a backend implementation, one can obtain the certificate.
 * @param {Name} keyName The name of the key.
 * @return {SyncPromise} A promise which returns the set of certificate names as
 * an array of Name. The Name objects are fresh copies. If the key does not
 * exist, return an empty array.
 */
PibMemory.prototype.getCertificatesOfKeyPromise = function(keyName)
{
  return SyncPromise.resolve(this.getCertificatesOfKey_(keyName));
};

/**
 * Do the work of getCertificatesOfKeyPromise.
 */
PibMemory.prototype.getCertificatesOfKey_ = function(keyName)
{
  var certificateNames = [];
  for (var certificateNameUri in this.certificates_) {
    if (CertificateV2.extractKeyNameFromCertName
        (this.certificates_[certificateNameUri].getName()).equals(keyName))
      certificateNames.push(new Name(certificateNameUri));
  }

  return certificateNames;
};

/**
 * Set the cert with name certificateName as the default for the key with
 * keyName.
 * @param {Name} keyName The name of the key.
 * @param {Name} certificateName The name of the certificate. This copies the
 * name.
 * @return {SyncPromise} A promise which fulfills when the default certificate
 * is set, or a promise rejected with Pib.Error if the certificate with name
 * certificateName does not exist.
 */
PibMemory.prototype.setDefaultCertificateOfKeyPromise = function
  (keyName, certificateName)
{
  if (!this.hasCertificate_(certificateName))
    return SyncPromise.reject(new Pib.Error(new Error
      ("Certificate `" + certificateName.toUri() +  "` does not exist")));

  // Copy the Name.
  this.defaultCertificateNames_[keyName.toUri()] = new Name(certificateName);
  return SyncPromise.resolve();
};

/**
 * Get the default certificate for the key with eyName.
 * @param {Name} keyName The name of the key.
 * @return {SyncPromise} A promise which returns a copy of the default
 * CertificateV2, or a promise rejected with Pib.Error if the default
 * certificate does not exist.
 */
PibMemory.prototype.getDefaultCertificateOfKeyPromise = function(keyName)
{
  var certificateName = this.defaultCertificateNames_[keyName.toUri()];
  if (certificateName == undefined)
    return SyncPromise.reject(new Pib.Error(new Error
      ("No default certificate for key `" + keyName.toUri() + "`")));

  var certificate = this.certificates_[certificateName.toUri()];
  return SyncPromise.resolve(new CertificateV2(certificate));
};
