/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/pib/certificate-container.cpp
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
var SyncPromise = require('../../util/sync-promise.js').SyncPromise; /** @ignore */
var CertificateV2 = require('../v2/certificate-v2.js').CertificateV2;

/**
 * A PibCertificateContainer is used to search/enumerate the certificates of a
 * key. (A PibCertificateContainer object can only be created by PibKey.)
 *
 * You should not call this private constructor. Instead, use
 * PibCertificateContainer.makePromise().
 *
 * @param {Name} keyName The name of the key, which is copied.
 * @param {PibImpl} pibImpl The PIB backend implementation.
 * @param {Array<Name>} certificateNames The set of certificate
 * names as an array of Name, as returned by getCertificatesOfKeyPromise.
 * @constructor
 */
var PibCertificateContainer = function PibCertificateContainer
  (keyName, pibImpl, certificateNames)
{
  // The cache of loaded certificates. certificateName URI string => CertificateV2.
  // (Use a string because we can't use the Name object as the key in JavaScript.)
  this.certificates_ = {};
  this.keyName_ = new Name(keyName);
  this.pibImpl_ = pibImpl;

  if (pibImpl == null)
    throw new Error("The pibImpl is null");

  // A set of Name URI string.
  // (Use a string because we can't use indexOf with a Name object.)
  this.certificateNameUris_ = [];
  for (var i in certificateNames)
    this.certificateNameUris_.push(certificateNames[i].toUri());
};

exports.PibCertificateContainer = PibCertificateContainer;

/**
 * Create a PibCertificateContainer for a key with keyName.
 * This method that returns a Promise is needed instead of a normal constructor
 * since it uses asynchronous PibImpl methods to initialize the object.
 * This method should only be called by PibKeyImpl.
 *
 * @param {Name} keyName The name of the key, which is copied.
 * @param {PibImpl} pibImpl The PIB backend implementation.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @param {Promise|SyncPromise} A promise which returns the new
 * PibCertificateContainer.
 */
PibCertificateContainer.makePromise = function(keyName, pibImpl, useSync)
{
  if (pibImpl == null)
    return SyncPromise.reject(new Error("The pibImpl is null"));

  return pibImpl.getCertificatesOfKeyPromise(keyName, useSync)
  .then(function(certificateNames) {
    return SyncPromise.resolve(new PibCertificateContainer
      (keyName, pibImpl, certificateNames));
  });
};

/**
 * Get the number of certificates in the container.
 * @return {number} The number of certificates.
 */
PibCertificateContainer.prototype.size = function()
{
  return this.certificateNameUris_.length;
};

/**
 * Add certificate into the container. If the certificate already exists, this
 * replaces it.
 * @param {CertificateV2} certificate The certificate to add. This copies the
 * object.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when finished, or a
 * promise rejected with Error if the name of the certificate does not match the
 * key name.
 */
PibCertificateContainer.prototype.addPromise = function(certificate, useSync)
{
  if (!this.keyName_.equals(certificate.getKeyName()))
    return SyncPromise.reject(new Error("The certificate name `" +
      certificate.getKeyName().toUri() + "` does not match the key name"));

  var certificateNameUri = certificate.getName().toUri();
  if (this.certificateNameUris_.indexOf(certificateNameUri) < 0)
    // Not already in the set.
    this.certificateNameUris_.push(certificateNameUri);

  // Copy the certificate.
  this.certificates_[certificateNameUri] =
    new CertificateV2(certificate);
  return this.pibImpl_.addCertificatePromise(certificate, useSync);
};

/**
 * Remove the certificate with name certificateName from the container. If the
 * certificate does not exist, do nothing.
 * @param {Name} certificateName The name of the certificate.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when finished, or a
 * promise rejected with Error if certificateName does not match the key name.
 */
PibCertificateContainer.prototype.removePromise = function
  (certificateName, useSync)
{
  if (!CertificateV2.isValidName(certificateName) ||
      !CertificateV2.extractKeyNameFromCertName(certificateName).equals
        (this.keyName_))
    return SyncPromise.reject(new Error("Certificate name `" +
      certificateName.toUri() + "` is invalid or does not match key name"));

  var certificateNameUri = certificateName.toUri();
  var index = this.certificateNameUris_.indexOf(certificateNameUri);
  // Do nothing if it doesn't exist.
  if (index >= 0)
    this.certificateNameUris_.splice(index, 1);

  delete this.certificates_[certificateNameUri];

  return this.pibImpl_.removeCertificatePromise(certificateName, useSync);
};

/**
 * Get the certificate with certificateName from the container.
 * @param {Name} certificateName The name of the certificate.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {SyncPromise} A promise which returns a copy of the CertificateV2, or
 * a promise rejected with Error if certificateName does not match the key name,
 * or a promise rejected with Pib.Error if the certificate does not exist.
 */
PibCertificateContainer.prototype.getPromise = function(certificateName, useSync)
{
  var certificateNameUri = certificateName.toUri();
  var cachedCertificate = this.certificates_[certificateNameUri];
  if (cachedCertificate != undefined)
    // Make a copy.
    // TODO: Copy is expensive. Can we just tell the caller not to modify it?
    return SyncPromise.resolve(new CertificateV2(cachedCertificate));

  // Get from the PIB and cache.
  if (!CertificateV2.isValidName(certificateName) ||
      !CertificateV2.extractKeyNameFromCertName(certificateName).equals
        (this.keyName_))
    return SyncPromise.reject(new Error("Certificate name `" +
      certificateName.toUri() + "` is invalid or does not match key name"));

  var thisContainer = this;

  return this.pibImpl_.getCertificatePromise(certificateName, useSync)
  .then(function(certificate) {
    thisContainer.certificates_[certificateNameUri] = certificate;
    // Make a copy.
    // TODO: Copy is expensive. Can we just tell the caller not to modify it?
    return SyncPromise.resolve(new CertificateV2(certificate));
  });
};
