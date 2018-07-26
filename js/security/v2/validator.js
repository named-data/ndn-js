/**
 * Copyright (C) 2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/validator.hpp
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
var SyncPromise = require('../../util/sync-promise.js').SyncPromise; /** @ignore */
var ValidationError = require('./validation-error.js').ValidationError; /** @ignore */
var CertificateFetcherOffline = require('./certificate-fetcher-offline.js').CertificateFetcherOffline; /** @ignore */
var CertificateStorage = require('./certificate-storage.js').CertificateStorage; /** @ignore */
var DataValidationState = require('./data-validation-state.js').DataValidationState; /** @ignore */
var InterestValidationState = require('./interest-validation-state.js').InterestValidationState; /** @ignore */
var Data = require('../../data.js').Data; /** @ignore */
var LOG = require('../../log.js').Log.LOG;

/**
 * The Validator class provides an interface for validating data and interest
 * packets.
 *
 * Every time a validation process is initiated, it creates a ValidationState
 * that exists until the validation finishes with either success or failure.
 * This state serves several purposes:
 * to record the Interest or Data packet being validated,
 * to record the failure callback,
 * to record certificates in the certification chain for the Interest or Data
 * packet being validated,
 * to record the names of the requested certificates in order to detect loops in
 * the certificate chain,
 * and to keep track of the validation chain size (also known as the validation
 * "depth").
 *
 * During validation, the policy and/or key fetcher can augment the validation
 * state with policy- and fetcher-specific information using tags.
 *
 * A Validator has a trust anchor cache to save static and dynamic trust
 * anchors, a verified certificate cache for saving certificates that are
 * already verified, and an unverified certificate cache for saving pre-fetched
 * but not yet verified certificates.
 *
 * Create a Validator with the policy and fetcher.
 * @param {ValidationPolicy} policy The validation policy to be associated with
 * this validator.
 * @param {CertificateFetcher} certificateFetcher (optional) The certificate
 * fetcher implementation. If omitted, use a CertificateFetcherOffline (assuming
 * that the validation policy doesn't need to fetch certificates).
 * @constructor
 */
var Validator = function Validator(policy, certificateFetcher)
{
  // Call the base constructor.
  CertificateStorage.call(this);

  if (certificateFetcher == undefined)
    certificateFetcher = new CertificateFetcherOffline();

  this.policy_ = policy;
  this.certificateFetcher_ = certificateFetcher;
  this.maxDepth_ = 25;

  if (this.policy_ == null)
    throw new Error("The policy is null");
  if (this.certificateFetcher_ == null)
    throw new Error("The certificateFetcher is null");

  this.policy_.setValidator(this);
  this.certificateFetcher_.setCertificateStorage(this);
};

Validator.prototype = new CertificateStorage();
Validator.prototype.name = "Validator";

exports.Validator = Validator;

/**
 * Get the ValidationPolicy given to the constructor.
 * @return {ValidationPolicy} The ValidationPolicy.
 */
Validator.prototype.getPolicy = function() { return this.policy_; };

/**
 * Get the CertificateFetcher given to (or created in) the constructor.
 * @return {CertificateFetcher} The CertificateFetcher.
 */
Validator.prototype.getFetcher = function() { return this.certificateFetcher_; };

/**
 * Set the maximum depth of the certificate chain.
 * @param {number} maxDepth The maximum depth.
 */
Validator.prototype.setMaxDepth = function(maxDepth)
{
  this.maxDepth_ = maxDepth;
};

/**
 * Get the maximum depth of the certificate chain.
 * @return {number} The maximum depth.
 */
Validator.prototype.getMaxDepth = function() { return this.maxDepth_; };

/**
 * Asynchronously validate the Data or Interest packet.
 * @param {Data|Interest} dataOrInterest The Data or Interest packet to validate,
 * which is copied.
 * @param {function} successCallback On validation success, this calls
 * successCallback(dataOrInterest).
 * @param {function} failureCallback On validation failure, this calls
 * failureCallback(dataOrInterest, error) where error is a ValidationError.
 */
Validator.prototype.validate = function
  (dataOrInterest, successCallback, failureCallback)
{
  var state;
  if (dataOrInterest instanceof Data) {
    state = new DataValidationState
      (dataOrInterest, successCallback, failureCallback);
    if (LOG > 3) console.log("Start validating data " +
      dataOrInterest.getName().toUri());
  }
  else {
    state = new InterestValidationState
      (dataOrInterest, successCallback, failureCallback);
    if (LOG > 3) console.log("Start validating interest " +
      dataOrInterest.getName().toUri());
  }

  var thisValidator = this;
  this.policy_.checkPolicy
    (dataOrInterest, state, function(certificateRequest, state) {
      if (certificateRequest == null)
        state.bypassValidation_();
      else
        // We need to fetch the key and validate it.
        thisValidator.requestCertificate_(certificateRequest, state);
    });
};

/**
 * Recursively validate the certificates in the certification chain.
 * @param {CertificateV2} certificate The certificate to check.
 * @param {ValidationState} state The current validation state.
 */
Validator.prototype.validateCertificate_ = function(certificate, state)
{
  if (LOG > 3) console.log("Start validating certificate " +
    certificate.getName().toUri());

  if (!certificate.isValid()) {
    state.fail(new ValidationError
      (ValidationError.EXPIRED_CERTIFICATE,
       "Retrieved certificate is not yet valid or expired `" +
       certificate.getName().toUri() + "`"));
    return;
  }

  var thisValidator = this;
  this.policy_.checkCertificatePolicy
    (certificate, state, function(certificateRequest, state) {
      if (certificateRequest == null)
        state.fail(new ValidationError
          (ValidationError.POLICY_ERROR,
           "Validation policy is not allowed to designate `" +
           certificate.getName().toUri() + "` as a trust anchor"));
      else {
        // We need to fetch the key and validate it.
        state.addCertificate(certificate);
        thisValidator.requestCertificate_(certificateRequest, state);
      }
    });
};

/**
 * Request a certificate for further validation.
 * @param {CertificateRequest} certificateRequest The certificate request.
 * @param {ValidationState} state The current validation state.
 */
Validator.prototype.requestCertificate_ = function(certificateRequest, state)
{
  if (state.getDepth() >= this.maxDepth_) {
    state.fail(new ValidationError
      (ValidationError.EXCEEDED_DEPTH_LIMIT, "Exceeded validation depth limit"));
    return;
  }

  if (state.hasSeenCertificateName(certificateRequest.interest_.getName())) {
    state.fail(new ValidationError
      (ValidationError.LOOP_DETECTED,
       "Validation loop detected for certificate `" +
         certificateRequest.interest_.getName().toUri() + "`"));
    return;
  }

  if (LOG > 3) console.log("Retrieving " +
    certificateRequest.interest_.getName().toUri());

  var thisValidator = this;

  var certificate = this.findTrustedCertificate(certificateRequest.interest_);
  if (certificate != null) {
    if (LOG > 3) console.log("Found trusted certificate " +
      certificate.getName().toUri());

    state.verifyCertificateChainPromise_(certificate)
    .then(function(certificate) {
      if (certificate != null)
        return state.verifyOriginalPacketPromise_(certificate);
      else
        return SyncPromise.resolve();
    })
    .then(function() {
      for (var i = 0; i < state.certificateChain_.length; ++i)
        thisValidator.cacheVerifiedCertificate(state.certificateChain_[i]);
    });

    return;
  }

  this.certificateFetcher_.fetch
    (certificateRequest, state, function(certificate, state) {
      thisValidator.validateCertificate_(certificate, state);
    });
};
