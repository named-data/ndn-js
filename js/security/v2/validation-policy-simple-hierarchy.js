/**
 * Copyright (C) 2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/validation-policy-simple-hierarchy.hpp
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
var CertificateRequest = require('./certificate-request.js').CertificateRequest; /** @ignore */
var ValidationError = require('./validation-error.js').ValidationError; /** @ignore */
var Interest = require('../../interest.js').Interest; /** @ignore */
var ValidationPolicy = require('./validation-policy.js').ValidationPolicy;

/**
 * ValidationPolicySimpleHierarchy extends ValidationPolicy to implement a
 * Validation policy for a simple hierarchical trust model.
 * @constructor
 */
var ValidationPolicySimpleHierarchy = function ValidationPolicySimpleHierarchy()
{
  // Call the base constructor.
  ValidationPolicy.call(this);
};

ValidationPolicySimpleHierarchy.prototype = new ValidationPolicy();
ValidationPolicySimpleHierarchy.prototype.name = "ValidationPolicySimpleHierarchy";

exports.ValidationPolicySimpleHierarchy = ValidationPolicySimpleHierarchy;

/**
 * @param {Data|Interest} dataOrInterest
 * @param {ValidationState} state
 * @param {function} continueValidation
 */
ValidationPolicySimpleHierarchy.prototype.checkPolicy = function
  (dataOrInterest, state, continueValidation)
{
  keyLocatorName = ValidationPolicy.getKeyLocatorName(dataOrInterest, state);
  if (state.isOutcomeFailed())
    // Already called state.fail().)
    return;

  if (keyLocatorName.getPrefix(-2).isPrefixOf(dataOrInterest.getName()))
    continueValidation(new CertificateRequest(new Interest(keyLocatorName)), state);
  else
    state.fail(new ValidationError(ValidationError.INVALID_KEY_LOCATOR,
      "Signing policy violation for " + dataOrInterest.getName().toUri() +
      " by " + keyLocatorName.toUri()));
};
