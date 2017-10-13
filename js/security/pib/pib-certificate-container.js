/**
 * Copyright (C) 2017 Regents of the University of California.
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
 * Create a CertificateContainer for a key with keyName. This constructor
 * should only be called by PibKeyImpl.
 *
 * @param {Name} keyName The name of the key, which is copied.
 * @param {PibImpl} pibImpl The PIB backend implementation.
 * @constructor
 */
var PibCertificateContainer = function PibCertificateContainer(keyName, pibImpl)
{
  // The cache of loaded certificates. certificateName URI string => CertificateV2.
  // (Use a string because we can't use the Name object as the key in JavaScript.)
  this.certificates_ = {};
  this.keyName_ = new Name(keyName);
  this.pibImpl_ = pibImpl;

  if (pibImpl == null)
    throw new Error("The pibImpl is null");

  // A set of Name URI string.
  // This will be initialized asynchronously by getCertificateNameUrisPromise_().
  // (Use a string because we can't use indexOf with a Name object.)
  this.certificateNameUris_ = null;
};

exports.PibCertificateContainer = PibCertificateContainer;

/**
 * Get the number of certificates in the container.
 * @return {Promise|SyncPromise} A promise which returns the number of
 * certificates.
 */
PibCertificateContainer.prototype.sizePromise = function()
{
  return this.getCertificateNameUrisPromise_()
  .then(function(certificateNameUris) {
    return SyncPromise.resolve(certificateNameUris.length);
  });
};

/**
 * Add certificate into the container. If the certificate already exists, this
 * replaces it.
 * @param {CertificateV2} certificate The certificate to add. This copies the
 * object.
 * @return {Promise|SyncPromise} A promise which fulfills when finished, or a
 * promise rejected with Error if the name of the certificate does not match the
 * key name.
 */
PibCertificateContainer.prototype.addPromise = function(certificate)
{
  if (!this.keyName_.equals(certificate.getKeyName()))
    return SyncPromise.reject(new Error("The certificate name `" +
      certificate.getKeyName().toUri() + "` does not match the key name"));

  var thisContainer = this;

  var certificateNameUri = certificate.getName().toUri();
  return this.getCertificateNameUrisPromise_()
  .then(function(certificateNameUris) {
    if (certificateNameUris.indexOf(certificateNameUri) < 0)
      // Not already in the set.
      certificateNameUris.push(certificateNameUri);

    // Copy the certificate.
    thisContainer.certificates_[certificateNameUri] =
      new CertificateV2(certificate);
    return thisContainer.pibImpl_.addCertificatePromise(certificate);
  });
};

/**
 * Remove the certificate with name certificateName from the container. If the
 * certificate does not exist, do nothing.
 * @param {Name} certificateName The name of the certificate.
 * @return {Promise|SyncPromise} A promise which fulfills when finished, or a
 * promise rejected with Error if certificateName does not match the key name.
 */
PibCertificateContainer.prototype.removePromise = function(certificateName)
{
  if (!CertificateV2.isValidName(certificateName) ||
      !CertificateV2.extractKeyNameFromCertName(certificateName).equals
        (this.keyName_))
    return SyncPromise.reject(new Error("Certificate name `" +
      certificateName.toUri() + "` is invalid or does not match key name"));

  var thisContainer = this;

  var certificateNameUri = certificateName.toUri();
  return this.getCertificateNameUrisPromise_()
  .then(function(certificateNameUris) {
    var index = certificateNameUris.indexOf(certificateNameUri);
    // Do nothing if it doesn't exist.
    if (index >= 0)
      certificateNameUris.splice(index, 1);

    delete thisContainer.certificates_[certificateNameUri];

    return thisContainer.pibImpl_.removeCertificatePromise(certificateName);
  });
};

/**
 * Get the certificate with certificateName from the container.
 * @param {Name} certificateName The name of the certificate.
 * @return {SyncPromise} A promise which returns a copy of the CertificateV2, or
 * a promise rejected with Error if certificateName does not match the key name,
 * or a promise rejected with Pib.Error if the certificate does not exist.
 */
PibCertificateContainer.prototype.getPromise = function(certificateName)
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

  return this.pibImpl_.getCertificatePromise(certificateName)
  .then(function(certificate) {
    thisContainer.certificates_[certificateNameUri] = certificate;
    // Make a copy.
    // TODO: Copy is expensive. Can we just tell the caller not to modify it?
    return SyncPromise.resolve(new CertificateV2(certificate));
  });
};

/**
 * If this.certificateNameUris_ is still null, initialize it asynchronously.
 * Otherwise, just return this.certificateNameUris_.
 * @return {Promise|SyncPromise} A promise which returns the set of certificate
 * names URIs as an array of strings.
 */
PibCertificateContainer.prototype.getCertificateNameUrisPromise_ = function()
{
  if (this.certificateNameUris_ !== null)
    return SyncPromise.resolve(this.certificateNameUris_);
  else {
    var thisContainer = this;

    return this.pibImpl_.getCertificatesOfKeyPromise(this.keyName_)
    .then(function(certificateNames) {
      thisContainer.certificateNameUris_ = [];
      for (var i in certificateNames)
        thisContainer.certificateNameUris_.push(certificateNames[i].toUri());

      return SyncPromise.resolve(thisContainer.certificateNameUris_);
    });
  }
};

