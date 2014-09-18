/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx security by Yingdi Yu <yingdi@cs.ucla.edu>.
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

/**
 * A PolicyManager is an abstract base class to represent the policy for
 * verifying data packets. You must create an object of a subclass.
 * @constructor
 */
var PolicyManager = function PolicyManager()
{
};

exports.PolicyManager = PolicyManager;

/**
 * Check if the received data packet or signed interest can escape from
 * verification and be trusted as valid.
 * Your derived class should override.
 *
 * @param {Data|Interest} dataOrInterest The received data packet or interest.
 * @returns {boolean} True if the data or interest does not need to be verified
 * to be trusted as valid, otherwise false.
 */
PolicyManager.prototype.skipVerifyAndTrust = function(dataOrInterest)
{
  throw new Error("PolicyManager.skipVerifyAndTrust is not implemented");
};

/**
 * Check if this PolicyManager has a verification rule for the received data
 * packet or signed interest.
 * Your derived class should override.
 *
 * @param {Data|Interest} dataOrInterest The received data packet or interest.
 * @returns {boolean} True if the data or interest must be verified, otherwise
 * false.
 */
PolicyManager.prototype.requireVerify = function(dataOrInterest)
{
  throw new Error("PolicyManager.requireVerify is not implemented");
};

/**
 * Check whether the received data packet complies with the verification policy,
 * and get the indication of the next verification step.
 * Your derived class should override.
 *
 * @param {Data|Interest} dataOrInterest The Data object or interest with the
 * signature to check.
 * @param {number} stepCount The number of verification steps that have been
 * done, used to track the verification progress.
 * @param {function} onVerified If the signature is verified, this calls
 * onVerified(data).
 * @param {function} onVerifyFailed If the signature check fails, this calls
 * onVerifyFailed(data).
 * @param {WireFormat} wireFormat
 * @returns {ValidationRequest} The indication of next verification step, or
 * null if there is no further step.
 */
PolicyManager.prototype.checkVerificationPolicy = function
  (dataOrInterest, stepCount, onVerified, onVerifyFailed, wireFormat)
{
  throw new Error("PolicyManager.checkVerificationPolicy is not implemented");
};

/**
 * Check if the signing certificate name and data name satisfy the signing
 * policy.
 * Your derived class should override.
 *
 * @param {Name} dataName The name of data to be signed.
 * @param {Name} certificateName The name of signing certificate.
 * @returns {boolean} True if the signing certificate can be used to sign the
 * data, otherwise false.
 */
PolicyManager.prototype.checkSigningPolicy = function(dataName, certificateName)
{
  throw new Error("PolicyManager.checkSigningPolicy is not implemented");
};

/**
 * Infer the signing identity name according to the policy. If the signing
 * identity cannot be inferred, return an empty name.
 * Your derived class should override.
 *
 * @param {Name} dataName The name of data to be signed.
 * @returns {Name} The signing identity or an empty name if cannot infer.
 */
PolicyManager.prototype.inferSigningIdentity = function(dataName)
{
  throw new Error("PolicyManager.inferSigningIdentity is not implemented");
};
