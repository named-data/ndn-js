/**
 * Copyright (C) 2014-2018 Regents of the University of California.
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

/** @ignore */
var Name = require('../../name.js').Name; /** @ignore */
var PolicyManager = require('./policy-manager.js').PolicyManager; /** @ignore */
var NdnCommon = require('../../util/ndn-common.js').NdnCommon;

/**
 * @constructor
 */
var NoVerifyPolicyManager = function NoVerifyPolicyManager()
{
  // Call the base constructor.
  PolicyManager.call(this);
};

NoVerifyPolicyManager.prototype = new PolicyManager();
NoVerifyPolicyManager.prototype.name = "NoVerifyPolicyManager";

exports.NoVerifyPolicyManager = NoVerifyPolicyManager;

/**
 * Override to always skip verification and trust as valid.
 *
 * @param {Data|Interest} dataOrInterest The received data packet or interest.
 * @return {boolean} True.
 */
NoVerifyPolicyManager.prototype.skipVerifyAndTrust = function(dataOrInterest)
{
  return true;
};

/**
 * Override to return false for no verification rule for the received data or
 * signed interest.
 *
 * @param {Data|Interest} dataOrInterest The received data packet or interest.
 * @return {boolean} False.
 */
NoVerifyPolicyManager.prototype.requireVerify = function(dataOrInterest)
{
  return false;
};

/**
 * Override to call onVerified(data) and to indicate no further verification
 * step.
 *
 * @param {Data|Interest} dataOrInterest The Data object or interest with the
 * signature to check.
 * @param {number} stepCount The number of verification steps that have been
 * done, used to track the verification progress.
 * @param {function} onVerified This does override to call
 * onVerified(dataOrInterest).
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onValidationFailed Override to ignore this.
 * @param {WireFormat} wireFormat
 * @return {ValidationRequest} null for no further step for looking up a
 * certificate chain.
 */
NoVerifyPolicyManager.prototype.checkVerificationPolicy = function
  (dataOrInterest, stepCount, onVerified, onValidationFailed, wireFormat)
{
  try {
    onVerified(dataOrInterest);
  } catch (ex) {
    console.log("Error in onVerified: " + NdnCommon.getErrorWithStackTrace(ex));
  }
  return null;
};

/**
 * Override to always indicate that the signing certificate name and data name
 * satisfy the signing policy.
 *
 * @param {Name} dataName The name of data to be signed.
 * @param {Name} certificateName The name of signing certificate.
 * @return {boolean} True to indicate that the signing certificate can be used
 * to sign the data.
 */
NoVerifyPolicyManager.prototype.checkSigningPolicy = function
  (dataName, certificateName)
{
  return true;
};

/**
 * Override to indicate that the signing identity cannot be inferred.
 *
 * @param {Name} dataName The name of data to be signed.
 * @return {Name} An empty name because cannot infer.
 */
NoVerifyPolicyManager.prototype.inferSigningIdentity = function(dataName)
{
  return new Name();
};
