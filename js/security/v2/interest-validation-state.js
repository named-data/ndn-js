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
var Interest = require('../../interest.js').Interest; /** @ignore */
var LOG = require('../../log.js').Log.LOG; /** @ignore */
var ValidationError = require('./validation-error.js').ValidationError; /** @ignore */
var ValidationState = require('./validation-state.js').ValidationState; /** @ignore */
var VerificationHelpers = require('../verification-helpers.js').VerificationHelpers; /** @ignore */
var NdnCommon = require('../../util/ndn-common.js').NdnCommon;

/**
 * The InterestValidationState class extends ValidationState to hold the
 * validation state for an Interest packet.
 *
 * Create an InterestValidationState for the Interest packet. The caller must
 * ensure that the state instance is valid until the validation finishes (i.e.,
 * until validateCertificateChain() and validateOriginalPacket() have been
 * called).
 * @param {Interest} interest The Interest packet being validated, which is copied.
 * @param {function} successCallback This calls successCallback(interest) to
 * report a successful Interest validation.
 * @param {function} failureCallback This calls failureCallback(interest, error)
 * to report a failed Interest validation, where error is a ValidationError.
 * @constructor
 */
var InterestValidationState = function InterestValidationState
  (interest, successCallback, failureCallback)
{
  // Call the base constructor.
  ValidationState.call(this);

  // Make a copy.
  this.interest_ = new Interest(interest);
  this.successCallbacks_ = [successCallback]; // of SuccessCallback function
  this.failureCallback_ = failureCallback;

  if (successCallback == null)
    throw new Error("The successCallback is null");
  if (this.failureCallback_ == null)
    throw new Error("The failureCallback is null");
};

InterestValidationState.prototype = new ValidationState();
InterestValidationState.prototype.name = "InterestValidationState";

exports.InterestValidationState = InterestValidationState;

/**
 * Call the failure callback.
 * @param {ValidationError} error
 */
InterestValidationState.prototype.fail = function(error)
{
  if (LOG > 3) console.log("" + error);
  try {
    this.failureCallback_(this.interest_, error);
  } catch (ex) {
    console.log("Error in failureCallback: " + NdnCommon.getErrorWithStackTrace(ex));
  }
  this.setOutcome(false);
};

/**
 * Get the original Interest packet being validated which was given to the
 * constructor.
 * @return {Interest} The original Interest packet.
 */
InterestValidationState.prototype.getOriginalInterest = function()
{
  return this.interest_;
};

/**
 * @param {function} successCallback This calls successCallback(interest).
 */
InterestValidationState.prototype.addSuccessCallback = function(successCallback)
{
  this.successCallbacks_.push(successCallback);
};

/**
 * Override to verify the Interest packet given to the constructor.
 * @param {CertificateV2} trustedCertificate The certificate that signs the
 * original packet.
 * @return {Promise|SyncPromise} A promise that resolves when the success or
 * failure callback has been called.
 */
InterestValidationState.prototype.verifyOriginalPacketPromise_ = function
  (trustedCertificate)
{
  var thisState = this;

  return VerificationHelpers.verifyInterestSignaturePromise
    (this.interest_, trustedCertificate)
  .then(function(verifySuccess) {
    if (verifySuccess) {
      if (LOG > 3) console.log("OK signature for interest `" +
        thisState.interest_.getName().toUri() + "`");
      for (var i = 0; i < thisState.successCallbacks_.length; ++i) {
        try {
          thisState.successCallbacks_[i](thisState.interest_);
        } catch (ex) {
          console.log("Error in successCallback: " + NdnCommon.getErrorWithStackTrace(ex));
        }
      }
      thisState.setOutcome(true);
    }
    else
      thisState.fail(new ValidationError(ValidationError.INVALID_SIGNATURE,
        "Invalid signature of interest `" +
        thisState.interest_.getName().toUri() + "`"));

    return SyncPromise.resolve();
  });
};

/**
 * Override to call the success callback using the Interest packet given to the
 * constructor.
 */
InterestValidationState.prototype.bypassValidation_ = function()
{
  if (LOG > 3) console.log("Signature verification bypassed for interest `" +
    this.interest_.getName().toUri() + "`");
  for (var i = 0; i < this.successCallbacks_.length; ++i) {
    try {
      this.successCallbacks_[i](this.interest_);
    } catch (ex) {
      console.log("Error in successCallback: " + NdnCommon.getErrorWithStackTrace(ex));
    }
  }
  this.setOutcome(true);
};
