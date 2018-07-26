/**
 * Copyright (C) 2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/validation-policy.hpp
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
var Data = require('../../data.js').Data; /** @ignore */
var KeyLocator = require('../../key-locator.js').KeyLocator; /** @ignore */
var KeyLocatorType = require('../../key-locator.js').KeyLocatorType; /** @ignore */
var WireFormat = require('../../encoding/wire-format.js').WireFormat; /** @ignore */
var ValidationError = require('./validation-error.js').ValidationError; /** @ignore */
var CertificateV2 = require('./certificate-v2.js').CertificateV2;

/**
 * ValidationPolicy is an abstract base class that implements a validation
 * policy for Data and Interest packets.
 * @constructor
 */
var ValidationPolicy = function ValidationPolicy()
{
  this.validator_ = null;
  this.innerPolicy_ = null;
};

exports.ValidationPolicy = ValidationPolicy;

/**
 * Set the inner policy.
 * Multiple assignments of the inner policy will create a "chain" of linked
 * policies. The inner policy from the latest invocation of setInnerPolicy
 * will be at the bottom of the policy list.
 * For example, the sequence `this.setInnerPolicy(policy1)` and
 * `this.setInnerPolicy(policy2)`, will result in
 * `this.innerPolicy_ == policy1`,
 * this.innerPolicy_.innerPolicy_ == policy2', and
 * `this.innerPolicy_.innerPolicy_.innerPolicy_ == null`.
 * @param {ValidationPolicy} innerPolicy
 * @throws Error if the innerPolicy is null.
 */
ValidationPolicy.prototype.setInnerPolicy = function(innerPolicy)
{
  if (innerPolicy == null)
    throw new Error("The innerPolicy argument cannot be null");

  if (this.validator_ != null)
    innerPolicy.setValidator(this.validator_);

  if (this.innerPolicy_ == null)
    this.innerPolicy_ = innerPolicy;
  else
    this.innerPolicy_.setInnerPolicy(innerPolicy);
};

/**
 * Check if the inner policy is set.
 * @return {boolean} True if the inner policy is set.
 */
ValidationPolicy.prototype.hasInnerPolicy = function()
{
  return this.innerPolicy_ != null;
};

/**
 * Get the inner policy. If the inner policy was not set, the behavior is
 * undefined.
 * @return {ValidationPolicy} The inner policy.
 */
ValidationPolicy.prototype.getInnerPolicy = function()
{
  return this.innerPolicy_;
};

/**
 * Set the validator to which this policy is associated. This replaces any
 * previous validator.
 * @param {Validator} validator The validator.
 */
ValidationPolicy.prototype.setValidator = function(validator)
{
  this.validator_ = validator;
  if (this.innerPolicy_ != null)
    this.innerPolicy_.setValidator(validator);
};

/**
 * Check the Data or Interest packet against the policy.
 * Your derived class must implement this.
 * Depending on the implementation of the policy, this check can be done
 * synchronously or asynchronously.
 * The semantics of checkPolicy are as follows:
 * If the packet violates the policy, then the policy should call
 * state.fail() with an appropriate error code and error description.
 * If the packet conforms to the policy and no further key retrievals are
 * necessary, then the policy should call continueValidation(null, state).
 * If the packet conforms to the policy and a key needs to be fetched, then
 * the policy should call
 * continueValidation({appropriate-key-request-instance}, state).
 * @param {Data|Interest} dataOrInterest The Data or Interest packet to check.
 * @param {ValidationState} state The ValidationState of this validation.
 * @param {function} continueValidation The policy should call
 * continueValidation() as described above.
 */
ValidationPolicy.prototype.checkPolicy = function
  (dataOrInterest, state, continueValidation)
{
  throw new Error("ValidationPolicy.checkPolicy is not implemented");
};

/**
 * Check the certificate against the policy.
 * This base class implementation just calls checkPolicy(certificate, ...). Your
 * derived class may override. Depending on implementation of the policy, this
 * check can be done synchronously or asynchronously. See the checkPolicy(Data)
 * documentation for the semantics.
 * @param {CertificateV2} certificate The certificate to check.
 * @param {ValidationState} state The ValidationState of this validation.
 * @param {function} continueValidation The policy should call
 * continueValidation() as described above.
 */
ValidationPolicy.prototype.checkCertificatePolicy = function
  (certificate, state, continueValidation)
{
  this.checkPolicy(certificate, state, continueValidation);
};

/** Extract the KeyLocator Name from a Data or signed Interest packet.
 * The SignatureInfo in the packet must contain a KeyLocator of type KEYNAME.
 * Otherwise, state.fail is invoked with INVALID_KEY_LOCATOR.
 * @param {Data|Interest} dataOrInterest The Data or Interest packet with the
 * KeyLocator.
 * @param {ValidationState} state On error, this calls state.fail and returns an
 * empty Name.
 * @return {Name} The KeyLocator name, or an empty Name for failure.
 */
ValidationPolicy.getKeyLocatorName = function(dataOrInterest, state)
{
  if (dataOrInterest instanceof Data) {
    var data = dataOrInterest;
    return ValidationPolicy.getKeyLocatorNameFromSignature_
      (data.getSignature(), state);
  }
  else {
    var interest = dataOrInterest;

    var name = interest.getName();
    if (name.size() < 2) {
      state.fail(new ValidationError(ValidationError.INVALID_KEY_LOCATOR,
        "Invalid signed Interest: name too short"));
      return new Name();
    }

    var signatureInfo;
    try {
      // TODO: Generalize the WireFormat.
      signatureInfo =
        WireFormat.getDefaultWireFormat().decodeSignatureInfoAndValue
        (interest.getName().get(-2).getValue().buf(),
         interest.getName().get(-1).getValue().buf());
    } catch (ex) {
      state.fail(new ValidationError(ValidationError.INVALID_KEY_LOCATOR,
        "Invalid signed Interest: " + ex));
      return new Name();
    }

    return ValidationPolicy.getKeyLocatorNameFromSignature_(signatureInfo, state);
  }
};

/**
 * A helper method for getKeyLocatorName.
 * @param {Signature} signatureInfo
 * @param {ValidationState} state
 * @return {Name}
 */
ValidationPolicy.getKeyLocatorNameFromSignature_ = function(signatureInfo, state)
{
  if (!KeyLocator.canGetFromSignature(signatureInfo)) {
    state.fail(new ValidationError
      (ValidationError.INVALID_KEY_LOCATOR, "KeyLocator is missing"));
    return new Name();
  }

  var keyLocator = KeyLocator.getFromSignature(signatureInfo);
  if (keyLocator.getType() != KeyLocatorType.KEYNAME) {
    state.fail(new ValidationError
      (ValidationError.INVALID_KEY_LOCATOR, "KeyLocator type is not Name"));
    return new Name();
  }

  return keyLocator.getKeyName();
};
