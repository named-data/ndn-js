/**
 * Copyright (C) 2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/validation-error.cpp
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
 * A ValidationError holds an error code and an optional detailed error message.
 *
 * Create a new ValidationError for the given code.
 * @param {number} code The code which is one of the standard error codes such as
 * ValidationError.INVALID_SIGNATURE, or a custom code if greater than or equal
 * to ValidationError.USER_MIN .
 * @param {string} info {optinal) The error message. If omitted, use an empty
 * string.
 * @constructor
 */
var ValidationError = function ValidationError(code, info)
{
  this.code_ = code;
  this.info_ = (info != undefined ? info : "");
};

exports.ValidationError = ValidationError;

ValidationError.NO_ERROR =                    0;
ValidationError.INVALID_SIGNATURE =           1;
ValidationError.NO_SIGNATURE =                2;
ValidationError.CANNOT_RETRIEVE_CERTIFICATE = 3;
ValidationError.EXPIRED_CERTIFICATE =         4;
ValidationError.LOOP_DETECTED =               5;
ValidationError.MALFORMED_CERTIFICATE =       6;
ValidationError.EXCEEDED_DEPTH_LIMIT =        7;
ValidationError.INVALID_KEY_LOCATOR =         8;
ValidationError.POLICY_ERROR =                9;
ValidationError.IMPLEMENTATION_ERROR =        255;
// Custom error codes should use >= USER_MIN.
ValidationError.USER_MIN =                    256;

/**
 * Get the error code given to the constructor.
 * @return The error code which is one of the standard error codes such as
 * ValidationError.INVALID_SIGNATURE, or a custom code if greater than or equal
 * to ValidationError.USER_MIN.
 */
ValidationError.prototype.getCode = function() { return this.code_; };

/**
 * Get the error message given to the constructor.
 * @return The error message, or "" if none.
 */
ValidationError.prototype.getInfo = function() { return this.info_; };

/**
 * Get a string representation of this ValidationError.
 * @return {string} The string representation.
 */
ValidationError.prototype.toString = function()
{
  var result;

  if (this.code_ === ValidationError.NO_ERROR)
    result = "No error";
  else if (this.code_ === ValidationError.INVALID_SIGNATURE)
    result = "Invalid signature";
  else if (this.code_ === ValidationError.NO_SIGNATURE)
    result = "Missing signature";
  else if (this.code_ === ValidationError.CANNOT_RETRIEVE_CERTIFICATE)
    result = "Cannot retrieve certificate";
  else if (this.code_ === ValidationError.EXPIRED_CERTIFICATE)
    result = "Certificate expired";
  else if (this.code_ === ValidationError.LOOP_DETECTED)
    result = "Loop detected in certification chain";
  else if (this.code_ === ValidationError.MALFORMED_CERTIFICATE)
    result = "Malformed certificate";
  else if (this.code_ === ValidationError.EXCEEDED_DEPTH_LIMIT)
    result = "Exceeded validation depth limit";
  else if (this.code_ === ValidationError.INVALID_KEY_LOCATOR)
    result = "Key locator violates validation policy";
  else if (this.code_ === ValidationError.POLICY_ERROR)
    result = "Validation policy error";
  else if (this.code_ === ValidationError.IMPLEMENTATION_ERROR)
    result = "Internal implementation error";
  else if (this.code_ >= ValidationError.USER_MIN)
    result = "Custom error code " + this.code_;
  else
    result = "Unrecognized error code " + this.code_;

  if (this.info_.length > 0)
    result += " (" + this.info_ + ")";

  return result;
};
