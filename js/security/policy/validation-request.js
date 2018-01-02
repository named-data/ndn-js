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

/**
 * A ValidationRequest is used to return information from
 * PolicyManager.checkVerificationPolicy.
 *
 * Create a new ValidationRequest with the given values.
 * @param {Interest} interest An interest for fetching more data.
 * @param {function} onVerified If the signature is verified, this calls
 * onVerified(data).
 * @param {function} onValidationFailed If the signature check fails, this calls
 * onValidationFailed(data, reason).
 * @param {number} retry The number of retrials when there is an interest timeout.
 * @param {number} stepCount  The number of verification steps that have been
 * done, used to track the verification progress.
 * @constructor
 */
var ValidationRequest = function ValidationRequest
  (interest, onVerified, onValidationFailed, retry, stepCount)
{
  this.interest = interest;
  this.onVerified = onVerified;
  this.onValidationFailed = onValidationFailed;
  this.retry = retry;
  this.stepCount = stepCount;
};

exports.ValidationRequest = ValidationRequest;
