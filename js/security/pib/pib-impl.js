/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/pib/pib-impl.cpp
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
var SyncPromise = require('../../util/sync-promise.js').SyncPromise;

/**
 * PibImpl is an abstract base class for the PIB implementation used by the Pib
 * class. This class defines the interface that an actual PIB implementation
 * should provide, for example PibMemory.
 * @constructor
 */
var PibImpl = function PibImpl()
{
};

exports.PibImpl = PibImpl;

/**
 * Create a PibImpl.Error which represents a non-semantic error in PIB
 * implementation processing. A subclass of PibImpl may throw a subclass of this
 * class when there's a non-semantic error, such as a storage problem.
 * Call with: throw new PibImpl.Error(new Error("message")).
 * @constructor
 * @param {Error} error The exception created with new Error.
 */
PibImpl.Error = function PibImplError(error)
{
  if (error) {
    error.__proto__ = PibImpl.Error.prototype;
    return error;
  }
};

PibImpl.Error.prototype = new Error();
PibImpl.Error.prototype.name = "PibImplError";

// TpmLocator management.

/**
 * Set the corresponding TPM information to tpmLocator. This method does not
 * reset the contents of the PIB.
 * @param {string} tpmLocator The TPM locator string.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when the TPM locator is set.
 */
PibImpl.prototype.setTpmLocatorPromise = function(tpmLocator, useSync)
{
  return SyncPromise.reject(new Error
    ("PibImpl.setTpmLocatorPromise is not implemented"));
};

/**
 * Get the TPM Locator.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the TPM locator string.
 */
PibImpl.prototype.getTpmLocatorPromise = function(useSync)
{
  return SyncPromise.reject(new Error
    ("PibImpl.getTpmLocatorPromise is not implemented"));
};

// Identity management.

/**
 * Check for the existence of an identity.
 * @param {Name} identityName The name of the identity.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns true if the identity exists,
 * otherwise false.
 */
PibImpl.prototype.hasIdentityPromise = function(identityName, useSync)
{
  return SyncPromise.reject(new Error
    ("PibImpl.hasIdentityPromise is not implemented"));
};

/**
 * Add the identity. If the identity already exists, do nothing. If no default
 * identity has been set, set the added identity as the default.
 * @param {Name} identityName The name of the identity to add. This copies the
 * name.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when the identity is added.
 */
PibImpl.prototype.addIdentityPromise = function(identityName, useSync)
{
  return SyncPromise.reject(new Error
    ("PibImpl.addIdentityPromise is not implemented"));
};

/**
 * Remove the identity and its related keys and certificates. If the default
 * identity is being removed, no default identity will be selected. If the
 * identity does not exist, do nothing.
 * @param {Name} identityName The name of the identity to remove.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when the identity is removed.
 */
PibImpl.prototype.removeIdentityPromise = function(identityName, useSync)
{
  return SyncPromise.reject(new Error
    ("PibImpl.removeIdentityPromise is not implemented"));
};

/**
 * Erase all certificates, keys, and identities.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when the identities are cleared.
 */
PibImpl.prototype.clearIdentitiesPromise = function(useSync)
{
  return SyncPromise.reject(new Error
    ("PibImpl.clearIdentitiesPromise is not implemented"));
};

/**
 * Get the names of all the identities.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns a fresh set of identity names
 * as an array of Name. The Name objects are fresh copies.
 */
PibImpl.prototype.getIdentitiesPromise = function(useSync)
{
  return SyncPromise.reject(new Error
    ("PibImpl.getIdentitiesPromise is not implemented"));
};

/**
 * Set the identity with the identityName as the default identity. If the
 * identity with identityName does not exist, then it will be created.
 * @param {Name} identityName The name for the default identity. This copies the
 * name.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when the default identity is
 * set.
 */
PibImpl.prototype.setDefaultIdentityPromise = function(identityName, useSync)
{
  return SyncPromise.reject(new Error
    ("PibImpl.setDefaultIdentityPromise is not implemented"));
};

/**
 * Get the default identity.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the Name of the default
 * identity as a fresh copy, or a promise rejected with Pib.Error for no default
 * identity.
 */
PibImpl.prototype.getDefaultIdentityPromise = function(useSync)
{
  return SyncPromise.reject(new Error
    ("PibImpl.getDefaultIdentityPromise is not implemented"));
};

// Key management.

/**
 * Check for the existence of a key with keyName.
 * @param {Name} keyName The name of the key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns true if the key exists,
 * otherwise false. Return false if the identity does not exist.
 */
PibImpl.prototype.hasKeyPromise = function(keyName, useSync)
{
  return SyncPromise.reject(new Error
    ("PibImpl.hasKeyPromise is not implemented"));
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
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when the key is added.
 */
PibImpl.prototype.addKeyPromise = function(identityName, keyName, key, useSync)
{
  return SyncPromise.reject(new Error
    ("PibImpl.addKeyPromise is not implemented"));
};

/**
 * Remove the key with keyName and its related certificates. If the key does not
 * exist, do nothing.
 * @param {Name} keyName The name of the key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when the key is removed.
 */
PibImpl.prototype.removeKeyPromise = function(keyName, useSync)
{
  return SyncPromise.reject(new Error
    ("PibImpl.removeKeyPromise is not implemented"));
};

/**
 * Get the key bits of a key with name keyName.
 * @param {Name} keyName The name of the key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the key bits as a Blob, or a
 * promise rejected with Pib.Error if the key does not exist.
 */
PibImpl.prototype.getKeyBitsPromise = function(keyName, useSync)
{
  return SyncPromise.reject(new Error
    ("PibImpl.getKeyBitsPromise is not implemented"));
};

/**
 * Get all the key names of the identity with the name identityName. The
 * returned key names can be used to create a KeyContainer. With a key name and
 * a backend implementation, one can create a Key front end instance.
 * @param {Name} identityName The name of the identity.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return SyncPromise} A promise which returns the set of key names as an array
 * of Name. The Name objects are fresh copies. If the identity does not exist,
 * return an empty array.
 */
PibImpl.prototype.getKeysOfIdentityPromise = function(identityName, useSync)
{
  return SyncPromise.reject(new Error
    ("PibImpl.getKeysOfIdentityPromise is not implemented"));
};

/**
 * Set the key with keyName as the default key for the identity with name
 * identityName.
 * @param {Name} identityName The name of the identity. This copies the name.
 * @param {Name} keyName The name of the key. This copies the name.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when the default key is set,
 * or a promise rejected with Pib.Error if the key does not exist.
 */
PibImpl.prototype.setDefaultKeyOfIdentityPromise = function
  (identityName, keyName, useSync)
{
  return SyncPromise.reject(new Error
    ("PibImpl.setDefaultKeyOfIdentityPromise is not implemented"));
};

/**
 * Get the name of the default key for the identity with name identityName.
 * @param {Name} identityName The name of the identity.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the name of the default key as
 * a fresh copy, or a promise rejected with Pib.Error if the identity does not
 * exist.
 */
PibImpl.prototype.getDefaultKeyOfIdentityPromise = function(identityName, useSync)
{
  return SyncPromise.reject(new Error
    ("PibImpl.getDefaultKeyOfIdentityPromise is not implemented"));
};

// Certificate management.

/**
 * Check for the existence of a certificate with name certificateName.
 * @param {Name} certificateName The name of the certificate.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns true if the certificate exists,
 * otherwise false.
 */
PibImpl.prototype.hasCertificatePromise = function(certificateName, useSync)
{
  return SyncPromise.reject(new Error
    ("PibImpl.hasCertificatePromise is not implemented"));
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
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when the certificate is added.
 */
PibImpl.prototype.addCertificatePromise = function(certificate, useSync)
{
  return SyncPromise.reject(new Error
    ("PibImpl.addCertificatePromise is not implemented"));
};

/**
 * Remove the certificate with name certificateName. If the certificate does not
 * exist, do nothing.
 * @param {Name} certificateName The name of the certificate.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when the certificate is
 * removed.
 */
PibImpl.prototype.removeCertificatePromise = function(certificateName, useSync)
{
  return SyncPromise.reject(new Error
    ("PibImpl.removeCertificatePromise is not implemented"));
};

/**
 * Get the certificate with name certificateName.
 * @param {Name} certificateName The name of the certificate.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the CertificateV2, or a promise
 * rejected with Pib.Error if the certificate does not exist.
 */
PibImpl.prototype.getCertificatePromise = function(certificateName, useSync)
{
  return SyncPromise.reject(new Error
    ("PibImpl.getCertificatePromise is not implemented"));
};

/**
 * Get a list of certificate names of the key with id keyName. The returned
 * certificate names can be used to create a PibCertificateContainer. With a
 * certificate name and a backend implementation, one can obtain the certificate.
 * @param {Name} keyName The name of the key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the set of certificate names as
 * an array of Name. The Name objects are fresh copies. If the key does not
 * exist, return an empty array.
 */
PibImpl.prototype.getCertificatesOfKeyPromise = function(keyName, useSync)
{
  return SyncPromise.reject(new Error
    ("PibImpl.getCertificatesOfKeyPromise is not implemented"));
};

/**
 * Set the cert with name certificateName as the default for the key with
 * keyName.
 * @param {Name} keyName The name of the key.
 * @param {Name} certificateName The name of the certificate. This copies the
 * name.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when the default certificate
 * is set, or a promise rejected with Pib.Error if the certificate with name
 * certificateName does not exist.
 */
PibImpl.prototype.setDefaultCertificateOfKeyPromise = function
  (keyName, certificateName, useSync)
{
  return SyncPromise.reject(new Error
    ("PibImpl.setDefaultCertificateOfKeyPromise is not implemented"));
};

/**
 * Get the default certificate for the key with eyName.
 * @param {Name} keyName The name of the key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns a copy of the default
 * CertificateV2, or a promise rejected with Pib.Error if the default
 * certificate does not exist.
 */
PibImpl.prototype.getDefaultCertificateOfKeyPromise = function(keyName, useSync)
{
  return SyncPromise.reject(new Error
    ("PibImpl.getDefaultCertificateOfKeyPromise is not implemented"));
};
