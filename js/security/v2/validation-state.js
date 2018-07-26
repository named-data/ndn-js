/**
 * Copyright (C) 2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/validation-state.hpp
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
var LOG = require('../../log.js').Log.LOG; /** @ignore */
var VerificationHelpers = require('../verification-helpers.js').VerificationHelpers; /** @ignore */
var CertificateV2 = require('./certificate-v2.js').CertificateV2;

/**
 * ValidationState is an abstract base class for DataValidationState and
 * InterestValidationState.
 *
 * One instance of the validation state is kept for the validation of the whole
 * certificate chain.
 *
 * The state collects the certificate chain that adheres to the selected
 * validation policy to validate data or interest packets. Certificate, data,
 * and interest packet signatures are verified only after the validator
 * determines that the chain terminates with a trusted certificate (a trusted
 * anchor or a previously validated certificate). This model allows filtering
 * out invalid certificate chains without incurring (costly) cryptographic
 * signature verification overhead and mitigates some forms of denial-of-service
 * attacks.
 *
 * A validation policy and/or key fetcher may add custom information associated
 * with the validation state using tags.
 * @constructor
 */
var ValidationState = function ValidationState()
{
  /**
   * Each certificate in the chain signs the next certificate. The last
   * certificate signs the original packet.
   */
  this.certificateChain_ = []; // of CertificateV2
  // The keys are the set of Name URI String, and each value is true.
  this.seenCertificateNameUris_ = {};
  this.hasOutcome_ = false;
  this.outcome_ = false;
};

exports.ValidationState = ValidationState;

/**
 * Check if validation failed or success has been called.
 * @return {boolean} True if validation failed or success has been called.
 */
ValidationState.prototype.hasOutcome = function() { return this.hasOutcome_; };

/**
 * Check if validation failed has been called.
 * @return {boolean} True if validation failed has been called, false if no
 * validation callbacks have been called or validation success was called.
 */
ValidationState.prototype.isOutcomeFailed = function()
{
  return this.hasOutcome_ && this.outcome_ == false;
};

/**
 * Check if validation success has been called.
 * @return {boolean} True if validation success has been called, false if no
 * validation callbacks have been called or validation failed was called.
 */
ValidationState.prototype.isOutcomeSuccess = function()
{
  return this.hasOutcome_ && this.outcome_ == true;
};

/**
 * Call the failure callback.
 * @param {ValidationError} error
 */
ValidationState.prototype.fail = function(error)
{
  throw new Error("ValidationState.fail is not implemented");
};

/**
 * Get the depth of the certificate chain.
 * @return {number} The depth of the certificate chain.
 */
ValidationState.prototype.getDepth = function()
{
  return this.certificateChain_.length;
};

/**
 * Check if certificateName has been previously seen, and record the supplied
 * name.
 * @param {Name} certificateName The certificate name, which is copied.
 * @return {boolean} True if certificateName has been previously seen.
 */
ValidationState.prototype.hasSeenCertificateName = function(certificateName)
{
  var certificateNameUri = certificateName.toUri();
  if (this.seenCertificateNameUris_[certificateNameUri] !== undefined)
    return true;
  else {
    this.seenCertificateNameUris_[certificateNameUri] = true;
    return false;
  }
};

/**
 * Add the certificate to the top of the certificate chain.
 * If the certificate chain is empty, then the certificate should be the
 * signer of the original packet. If the certificate chain is not empty, then
 * the certificate should be the signer of the front of the certificate chain.
 * @note This function does not verify the signature bits.
 * @param {CertificateV2} certificate The certificate to add, which is copied.
 */
ValidationState.prototype.addCertificate = function(certificate)
{
  this.certificateChain_.unshift(new CertificateV2(certificate));
};

/**
 * Set the outcome to the given value, and set hasOutcome_ true.
 * @param {boolean} outcome The outcome.
 * @throws Error If this ValidationState already has an outcome.
 */
ValidationState.prototype.setOutcome = function(outcome)
{
  if (this.hasOutcome_)
    throw new Error("The ValidationState already has an outcome");

  this.hasOutcome_ = true;
  this.outcome_ = outcome;
};

/**
 * Verify the signature of the original packet. This is only called by the
 * Validator class.
 * @param {CertificateV2} trustedCertificate The certificate that signs the
 * original packet.
 * @return {Promise|SyncPromise} A promise that resolves when the success or
 * failure callback has been called.
 */
ValidationState.prototype.verifyOriginalPacketPromise_ = function
  (trustedCertificate)
{
  return SyncPromise.reject(new Error
    ("ValidationState.verifyOriginalPacketPromise_ is not implemented"));
};

/**
 * Call the success callback of the original packet without signature
 * validation. This is only called by the Validator class.
 */
ValidationState.prototype.bypassValidation_ = function()
{
  throw new Error("ValidationState.bypassValidation_ is not implemented");
};

/**
 * Verify signatures of certificates in the certificate chain. On return, the
 * certificate chain contains a list of certificates successfully verified by
 * trustedCertificate.
 * When the certificate chain cannot be verified, this method will call
 * fail() with the INVALID_SIGNATURE error code and the appropriate message.
 * This is only called by the Validator class.
 * @param {CertificateV2} trustedCertificate
 * @return {Promise|SyncPromise} A promise which returns the CertificateV2 to
 * validate the original data packet, either the last entry in the certificate
 * chain or trustedCertificate if the certificate chain is empty. However,
 * return a promise which returns null if the signature of at least one
 * certificate in the chain is invalid, in which case all unverified
 * certificates have been removed from the certificate chain.
 */
ValidationState.prototype.verifyCertificateChainPromise_ = function
  (trustedCertificate)
{
  var validatedCertificate = trustedCertificate;
  var thisState = this;

  // We're using Promises, so we need a function for the loop.
  var loopPromise = function(i) {
    if (i >= thisState.certificateChain_.length)
      // Finished.
      return SyncPromise.resolve(validatedCertificate);

    var certificateToValidate = thisState.certificateChain_[i];

    return VerificationHelpers.verifyDataSignaturePromise
      (certificateToValidate, validatedCertificate)
    .then(function(verifySuccess) {
      if (!verifySuccess) {
        thisState.fail(new ValidationError(ValidationError.INVALID_SIGNATURE,
             "Invalid signature of certificate `" +
             certificateToValidate.getName().toUri() + "`"));
        // Remove this and remaining certificates in the chain.
        while (thisState.certificateChain_.length > i)
          thisState.certificateChain_.splice(i, 1);

        return SyncPromise.resolve(null);
      }
      else {
        if (LOG > 3) console.log("OK signature for certificate `" +
          certificateToValidate.getName().toUri() + "`");
        validatedCertificate = certificateToValidate;
      }

      ++i;
      // Recurse to the next iteration.
      return loopPromise(i);
    });
  };

  return loopPromise(0);
};
