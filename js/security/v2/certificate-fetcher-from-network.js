/**
 * Copyright (C) 2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/certificate-fetcher-from-network.cpp
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
var LOG = require('../../log.js').Log.LOG; /** @ignore */
var CertificateV2 = require('./certificate-v2.js').CertificateV2; /** @ignore */
var ValidationError = require('./validation-error.js').ValidationError; /** @ignore */
var CertificateFetcher = require('./certificate-fetcher.js').CertificateFetcher;

/**
 * CertificateFetcherFromNetwork extends CertificateFetcher to fetch missing
 * certificates from the network.
 *
 * Create a CertificateFetcherFromNetwork to fetch certificates using the Face.
 * @param {Face} face The face for calling expressInterest.
 * @constructor
 */
var CertificateFetcherFromNetwork = function CertificateFetcherFromNetwork(face)
{
  // Call the base constructor.
  CertificateFetcher.call(this);

  this.face_ = face;
};

CertificateFetcherFromNetwork.prototype = new CertificateFetcher();
CertificateFetcherFromNetwork.prototype.name = "CertificateFetcherFromNetwork";

exports.CertificateFetcherFromNetwork = CertificateFetcherFromNetwork;

/**
 * Implement doFetch to use face_.expressInterest to fetch a certificate.
 * @param {CertificateRequest} certificateRequest The the request with the
 * Interest for fetching the certificate.
 * @param {ValidationState} state The validation state.
 * @param {function} continueValidation After fetching, this calls
 * continueValidation.continueValidation(certificate, state) where certificate
 * is the fetched certificate and state is the ValidationState.
 */
CertificateFetcherFromNetwork.prototype.doFetch_ = function
  (certificateRequest, state, continueValidation)
{
  var thisFetcher = this;
  try {
    thisFetcher.face_.expressInterest
      (certificateRequest.interest_,
      function(interest, data) {
        if (LOG > 3) console.log("Fetched certificate from network " +
          data.getName().toUri());

        var certificate;
        try {
          certificate = new CertificateV2(data);
        } catch (ex) {
          state.fail(new ValidationError
            (ValidationError.MALFORMED_CERTIFICATE,
             "Fetched a malformed certificate `" + data.getName().toUri() +
             "` (" + ex + ")"));
          return;
        }

        try {
          continueValidation(certificate, state);
        } catch (ex) {
          state.fail(new ValidationError
            (ValidationError.CANNOT_RETRIEVE_CERTIFICATE,
             "Error in continueValidation: " + ex));
        }
      },
      function(interest) {
        if (LOG > 3) console.log("Timeout while fetching certificate " +
          certificateRequest.interest_.getName().toUri() + ", retrying");

        --certificateRequest.nRetriesLeft_;
        if (certificateRequest.nRetriesLeft_ >= 0) {
          try {
            thisFetcher.fetch(certificateRequest, state, continueValidation);
          } catch (ex) {
             state.fail(new ValidationError
               (ValidationError.CANNOT_RETRIEVE_CERTIFICATE,
                "Error in fetch: " + ex));
          }
        }
        else
          state.fail(new ValidationError
            (ValidationError.CANNOT_RETRIEVE_CERTIFICATE,
             "Cannot fetch certificate after all retries `" +
             certificateRequest.interest_.getName().toUri() + "`"));
      },
      function(interest, networkNack) {
        if (LOG > 3) console.log("NACK (" + networkNack.getReason() +
          ") while fetching certificate " +
          certificateRequest.interest_.getName().toUri());

        --certificateRequest.nRetriesLeft_;
        if (certificateRequest.nRetriesLeft_ >= 0) {
          try {
            thisFetcher.fetch(certificateRequest, state, continueValidation);
          } catch (ex) {
             state.fail(new ValidationError
               (ValidationError.CANNOT_RETRIEVE_CERTIFICATE,
                "Error in fetch: " + ex));
          }
        }
        else
          state.fail(new ValidationError
            (ValidationError.CANNOT_RETRIEVE_CERTIFICATE,
             "Cannot fetch certificate after all retries `" +
             certificateRequest.interest_.getName().toUri() + "`"));
      });
  } catch (ex) {
    state.fail(new ValidationError(ValidationError.CANNOT_RETRIEVE_CERTIFICATE,
      "Error in expressInterest: " + ex));
  }
};
