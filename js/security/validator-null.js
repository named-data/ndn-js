/**
 * Copyright (C) 2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/validator-null.hpp
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
var ValidationPolicyAcceptAll = require('./v2/validation-policy-accept-all.js').ValidationPolicyAcceptAll; /** @ignore */
var CertificateFetcherOffline = require('./v2/certificate-fetcher-offline.js').CertificateFetcherOffline; /** @ignore */
var Validator = require('./v2/validator.js').Validator;

/**
 * A ValidatorNull extends Validator with an "accept-all" policy and an offline
 * certificate fetcher.
 * @constructor
 */
var ValidatorNull = function ValidatorNull()
{
  // Call the base constructor.
  Validator.call
    (this, new ValidationPolicyAcceptAll(), new CertificateFetcherOffline());
};

ValidatorNull.prototype = new Validator(new ValidationPolicyAcceptAll());
ValidatorNull.prototype.name = "ValidatorNull";

exports.ValidatorNull = ValidatorNull;
