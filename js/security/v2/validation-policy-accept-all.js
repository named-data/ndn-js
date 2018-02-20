/**
 * Copyright (C) 2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/validation-policy-accept-all.hpp
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
var ValidationPolicy = require('./validation-policy.js').ValidationPolicy;

/**
 * ValidationPolicyAcceptAll extends ValidationPolicy to implement a validator
 * policy that accepts any signature of a Data or Interest packet.
 * @constructor
 */
var ValidationPolicyAcceptAll = function ValidationPolicyAcceptAll()
{
  // Call the base constructor.
  ValidationPolicy.call(this);
};

ValidationPolicyAcceptAll.prototype = new ValidationPolicy();
ValidationPolicyAcceptAll.prototype.name = "ValidationPolicyAcceptAll";

exports.ValidationPolicyAcceptAll = ValidationPolicyAcceptAll;

/**
 * @param {Data|Interest} dataOrInterest
 * @param {ValidationState} state
 * @param {function} continueValidation
 */
ValidationPolicyAcceptAll.prototype.checkPolicy = function
  (dataOrInterest, state, continueValidation)
{
  continueValidation(null, state);
};
