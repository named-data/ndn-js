/**
 * Copyright (C) 2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/certificate-fetcher.hpp
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
var LOG = require('../../log.js').Log.LOG;

/**
 * CertificateFetcher is an abstract base class which provides an interface used
 * by the validator to fetch missing certificates.
 * @constructor
 */
var CertificateFetcher = function CertificateFetcher()
{
  this.certificateStorage_ = null;
};

exports.CertificateFetcher = CertificateFetcher;

/**
 * Assign the certificate storage used to check for known certificates and to
 * cache unverified ones.
 * @param {CertificateStorage} certificateStorage The certificate storage object
 * which must be valid for the lifetime of this CertificateFetcher.
 */
CertificateFetcher.prototype.setCertificateStorage = function(certificateStorage)
{
  this.certificateStorage_ = certificateStorage;
};

/**
 * Asynchronously fetch a certificate. setCertificateStorage must have been
 * called first.
 * If the requested certificate exists in the storage, then this method will
 * immediately call continueValidation with the certificate. If certificate is
 * not available, then the implementation-specific doFetch will be called to
 * asynchronously fetch the certificate. The successfully-retrieved
 * certificate will be automatically added to the unverified cache of the
 * certificate storage.
 * When the requested certificate is retrieved, continueValidation is called.
 * Otherwise, the fetcher implementation calls state.failed() with the
 * appropriate error code and diagnostic message.
 * @param {CertificateRequest} certificateRequest The the request with the
 * Interest for fetching the certificate.
 * @param {ValidationState} state The validation state.
 * @param {function} continueValidation After fetching, this calls
 * continueValidation(certificate, state) where certificate is the fetched
 * certificate and state is the ValidationState.
 */
CertificateFetcher.prototype.fetch = function
  (certificateRequest, state, continueValidation)
{
  if (this.certificateStorage_ == null)
    throw new Error
      ("CertificateFetcher.fetch: You must first call setCertificateStorage");

  var certificate =
    this.certificateStorage_.getUnverifiedCertificateCache().find
      (certificateRequest.interest_);
  if (certificate != null) {
     if (LOG > 3) console.log("Found certificate in **un**verified key cache " +
        certificate.getName().toUri());
    continueValidation(certificate, state);
    return;
  }

  var thisFetcher = this;
  // Fetch asynchronously.
  this.doFetch_
    (certificateRequest, state, function(certificate, state) {
      thisFetcher.certificateStorage_.cacheUnverifiedCertificate(certificate);
      continueValidation(certificate, state);
    });
};

/**
 * An implementation to fetch a certificate asynchronously. The subclass must
 * implement this method.
 * @param {CertificateRequest} certificateRequest The the request with the
 * Interest for fetching the certificate.
 * @param {ValidationState} state The validation state.
 * @param {function} continueValidation After fetching, this calls
 * continueValidation(certificate, state) where certificate is the fetched
 * certificate and state is the ValidationState.
 */
CertificateFetcher.prototype.doFetch_ = function
  (certificateRequest, state, continueValidation)
{
  throw new Error("CertificateFetcher.doFetch_ is not implemented");
};
