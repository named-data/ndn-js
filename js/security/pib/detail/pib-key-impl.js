/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/pib/detail/key-impl.cpp
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
var Name = require('../../../name.js').Name; /** @ignore */
var PublicKey = require('../../certificate/public-key.js').PublicKey; /** @ignore */
var Blob = require('../../../util/blob.js').Blob; /** @ignore */
var Pib = require('../pib.js').Pib; /** @ignore */
var PibKey = require('../pib-key.js').PibKey; /** @ignore */
var PibImpl = require('../pib-impl.js').PibImpl; /** @ignore */
var PibCertificateContainer = require('../pib-certificate-container.js').PibCertificateContainer; /** @ignore */
var SyncPromise = require('../../../util/sync-promise.js').SyncPromise;

/**
 * A PibKeyImpl provides the backend implementation for PibKey. A PibKey has
 * only one backend instance, but may have multiple frontend handles. Each
 * frontend handle is associated with the only one backend PibKeyImpl.
 *
 * You should not call this private constructor. Instead, use
 * PibKeyImpl.makePromise().
 *
 * @constructor
 */
var PibKeyImpl = function PibKeyImpl()
{
  // makePromise will set the fields.
};

exports.PibKeyImpl = PibKeyImpl;

/**
 * Create a PibKeyImpl. This method has two forms:
 * PibKeyImpl(keyName, keyEncoding, pibImpl, useSync) - Create a PibKeyImpl with
 * keyName. If the key does not exist in the backend implementation, add it by
 * creating it from the keyEncoding. If a key with keyName already exists,
 * overwrite it.
 * PibKeyImpl(keyName, pibImpl, useSync) - Create a PibKeyImpl with keyName.
 * Initialize the cached key encoding with pibImpl.getKeyBits().
 * This method that returns a Promise is needed instead of a normal constructor
 * since it uses asynchronous PibImpl methods to initialize the object.
 *
 * @param {Name} keyName The name of the key, which is copied.
 * @param {Buffer} keyEncoding The buffer of encoded key bytes, which is copied.
 * (This is only used in the constructor form
 * PibKeyImpl(keyName, keyEncoding, pibImpl) .)
 * @param {PibImpl) pibImpl: The Pib backend implementation.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @param {Promise|SyncPromise} A promise which returns the new PibKeyImpl, or a
 * promise which is rejected with Pib.Error if the constructor is the form
 * PibKeyImpl(keyName, pibImpl) (without the keyEncoding) and the key with
 * keyName does not exist.
 */
PibKeyImpl.makePromise = function(keyName, arg2, arg3, arg4)
{
  var pibKeyImpl = new PibKeyImpl();

  pibKeyImpl.defaultCertificate_ = null;

  if (arg2 instanceof PibImpl) {
    // PibKeyImpl(keyName, pibImpl, useSync)
    var pibImpl = arg2;
    var useSync = arg3;

    if (pibImpl == null)
      return SyncPromise.reject(new Error("The pibImpl is null"));

    return PibCertificateContainer.makePromise(keyName, pibImpl, useSync)
    .then(function(container) {
      pibKeyImpl.identityName_ = PibKey.extractIdentityFromKeyName(keyName);
      pibKeyImpl.keyName_ = new Name(keyName);
      pibKeyImpl.pibImpl_ = pibImpl;
      pibKeyImpl.certificates_ = container;

      return pibKeyImpl.pibImpl_.getKeyBitsPromise(pibKeyImpl.keyName_, useSync);
    })
    .then(function(keyBits) {
      pibKeyImpl.keyEncoding_ = keyBits;

      try {
        publicKey = new PublicKey(pibKeyImpl.keyEncoding_);
      }
      catch (ex) {
        // We don't expect this since we just fetched the encoding.
        return SyncPromise.reject(new Pib.Error(new Error
          ("Error decoding public key")));
      }

      pibKeyImpl.keyType_ = publicKey.getKeyType();

      return SyncPromise.resolve(pibKeyImpl);
    });
  }
  else {
    // PibKeyImpl(keyName, keyEncoding, pibImpl)
    var keyEncoding = arg2;
    var pibImpl = arg3;
    var useSync = arg4;

    if (pibImpl == null)
      return SyncPromise.reject(new Error("The pibImpl is null"));

    return PibCertificateContainer.makePromise(keyName, pibImpl, useSync)
    .then(function(container) {
      pibKeyImpl.identityName_ = PibKey.extractIdentityFromKeyName(keyName);
      pibKeyImpl.keyName_ = new Name(keyName);
      pibKeyImpl.keyEncoding_ = new Blob(keyEncoding, true);
      pibKeyImpl.pibImpl_ = pibImpl;
      pibKeyImpl.certificates_ = container;

      try {
        publicKey = new PublicKey(pibKeyImpl.keyEncoding_);
        pibKeyImpl.keyType_ = publicKey.getKeyType();
      }
      catch (ex) {
        return SyncPromise.reject(new Error("Invalid key encoding"));
      }

      return pibKeyImpl.pibImpl_.addKeyPromise
        (pibKeyImpl.identityName_, pibKeyImpl.keyName_, keyEncoding, useSync);
    })
    .then(function() {
      return SyncPromise.resolve(pibKeyImpl);
    });
  }
};

/**
 * Get the key name.
 * @return {Name} The key name. You must not change the object. If you need to
 * change it, make a copy.
 */
PibKeyImpl.prototype.getName = function() { return this.keyName_; };

/**
 * Get the name of the identity this key belongs to.
 * @return {Name} The name of the identity. You must not change the object. If
 * you need to change it, make a copy.
 */
PibKeyImpl.prototype.getIdentityName = function() { return this.identityName_; };

/**
 * Get the key type.
 * @return {number} The key type as an int from the KeyType enum.
 */
PibKeyImpl.prototype.getKeyType = function() { return this.keyType_; };

/**
 * Get the public key encoding.
 * @return {Blob} The public key encoding.
 */
PibKeyImpl.prototype.getPublicKey = function() { return this.keyEncoding_; };

/**
 * Add the certificate. If a certificate with the same name (without implicit
 * digest) already exists, then overwrite the certificate. If no default
 * certificate for the key has been set, then set the added certificate as
 * default for the key.
 * @param {CertificateV2} certificate The certificate to add. This copies
 * the object.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when finished, or a
 * promise rejected with Error if the name of the certificate does not match the
 * key name.
 */
PibKeyImpl.prototype.addCertificatePromise = function(certificate, useSync)
{
  return this.certificates_.addPromise(certificate, useSync);
};

/**
 * Remove the certificate with name certificateName. If the certificate does not
 * exist, do nothing.
 * @param {Name} certificateName The name of the certificate.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when finished, or a
 * promise rejected with Error if certificateName does not match the key name.
 */
PibKeyImpl.prototype.removeCertificatePromise = function(certificateName, useSync)
{
  if (this.defaultCertificate_ !== null &&
      this.defaultCertificate_.getName().equals(certificateName))
    this.defaultCertificate_ = null;

  return this.certificates_.removePromise(certificateName, useSync);
};

/**
 * Get the certificate with name certificateName.
 * @param {Name} certificateName The name of the certificate.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns a copy of the
 * CertificateV2, or a promise rejected with Error if certificateName does not
 * match the key name, or a promise rejected with Pib.Error if the certificate
 * does not exist.
 */
PibKeyImpl.prototype.getCertificatePromise = function(certificateName, useSync)
{
  return this.certificates_.getPromise(certificateName, useSync);
};

/**
 * Set the existing certificate as the default certificate.
 * @param {Name|CertificateV2} certificateOrCertificateName If
 * certificateOrCertificateName is a Name, it is the name of the certificate,
 * which must exist. Otherwise certificateOrCertificateName is the CertificateV2
 * to add (if necessary) and set as the default.
 * @param {Name} certificateName The name of the certificate.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the default
 * CertificateV2, or a promise rejected with Error if certificateName does not
 * match the key name, or a promise rejected with Pib.Error if
 * certificateOrCertificateName is the certificate Name and the certificate does
 * not exist.
 */
PibKeyImpl.prototype.setDefaultCertificatePromise = function
  (certificateOrCertificateName, useSync)
{
  var thisImpl = this;
  var certificateName;

  return SyncPromise.resolve()
  .then(function() {
    if (certificateOrCertificateName instanceof Name)
      return SyncPromise.resolve(certificateOrCertificateName);
    else {
      var certificate = certificateOrCertificateName;
      return thisImpl.addCertificatePromise(certificate)
      .then(function() {
        return SyncPromise.resolve(certificate.getName());
      });
    }
  })
  .then(function(localCertificateName) {
    certificateName = localCertificateName;
    return thisImpl.certificates_.getPromise(certificateName, useSync);
  })
  .then(function(certificate) {
    thisImpl.defaultCertificate_ = certificate;
    return thisImpl.pibImpl_.setDefaultCertificateOfKeyPromise
      (thisImpl.keyName_, certificateName, useSync);
  })
  .then(function() {
    return SyncPromise.resolve(thisImpl.defaultCertificate_);
  });
};

/**
 * Get the default certificate for this Key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the default
 * CertificateV2, or a promise rejected with Pib.Error if the default
 * certificate does not exist.
 */
PibKeyImpl.prototype.getDefaultCertificatePromise = function(useSync)
{
  var thisImpl = this;

  if (this.defaultCertificate_ === null) {
    return this.pibImpl_.getDefaultCertificateOfKeyPromise(this.keyName_, useSync)
    .then(function(certificate) {
      thisImpl.defaultCertificate_ = certificate;
      return SyncPromise.resolve(thisImpl.defaultCertificate_);
    });
  }
  else
    return SyncPromise.resolve(thisImpl.defaultCertificate_);
};
