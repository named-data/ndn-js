/**
 * Copyright (C) 2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
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
var Interest = require('../../interest.js').Interest; /** @ignore */
var CertificateRequest = require('./certificate-request.js').CertificateRequest; /** @ignore */
var PibKey = require('../pib/pib-key.js').PibKey; /** @ignore */
var ValidationError = require('./validation-error.js').ValidationError; /** @ignore */
var ValidationPolicy = require('./validation-policy.js').ValidationPolicy;

/**
 * ValidationPolicyFromPib extends ValidationPolicy to implement a validator
 * policy that validates a packet using the default certificate of the key in
 * the PIB that is named by the packet's KeyLocator.
 *
 * Create a ValidationPolicyFromPib to use the given PIB.
 * @param {Pib} pib The PIB with certificates.
 * @constructor
 */
var ValidationPolicyFromPib = function ValidationPolicyFromPib(pib)
{
  // Call the base constructor.
  ValidationPolicy.call(this);

  this.pib_ = pib;
};

ValidationPolicyFromPib.prototype = new ValidationPolicy();
ValidationPolicyFromPib.prototype.name = "ValidationPolicyFromPib";

exports.ValidationPolicyFromPib = ValidationPolicyFromPib;

/**
 * @param {Data|Interest} dataOrInterest
 * @param {ValidationState} state
 * @param {function} continueValidation
 */
ValidationPolicyFromPib.prototype.checkPolicy = function
  (dataOrInterest, state, continueValidation)
{
  var keyName = ValidationPolicy.getKeyLocatorName(dataOrInterest, state);
  if (state.isOutcomeFailed())
    // Already called state.fail() .
    return;

  this.checkPolicyHelper_(keyName, state, continueValidation);
};

ValidationPolicyFromPib.prototype.checkPolicyHelper_ = function
  (keyName, state, continueValidation)
{
  var identity;
  try {
    identity = this.pib_.getIdentity(PibKey.extractIdentityFromKeyName(keyName));
  } catch (ex) {
    state.fail(new ValidationError
      (ValidationError.CANNOT_RETRIEVE_CERTIFICATE,
       "Cannot get the PIB identity for key " + keyName.toUri() + ": " + ex));
    return;
  }

  var key;
  try {
    key = identity.getKey(keyName);
  } catch (ex) {
    state.fail(new ValidationError
      (ValidationError.CANNOT_RETRIEVE_CERTIFICATE,
       "Cannot get the PIB key " + keyName.toUri() + ": " + ex));
    return;
  }

  var certificate;
  try {
    certificate = key.getDefaultCertificate();
  } catch (ex) {
    state.fail(new ValidationError
      (ValidationError.CANNOT_RETRIEVE_CERTIFICATE,
       "Cannot get the default certificate for key " + keyName.toUri() + ": " +
       ex));
    return;
  }

  // Add the certificate as the temporary trust anchor.
  this.validator_.resetAnchors();
  this.validator_.loadAnchor("", certificate);
  continueValidation(new CertificateRequest(new Interest(keyName)), state);
  // Clear the temporary trust anchor.
  this.validator_.resetAnchors();
};
