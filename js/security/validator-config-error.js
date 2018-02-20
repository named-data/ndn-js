/**
 * Copyright (C) 2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/validator-config/common.hpp
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
 * Create a new ValidatorConfigError to report an  error using ValidatorConfig.
 * Call with: throw new ValidatorConfigError(new Error("message")).
 * @param {Error} error The exception created with new Error.
 * @constructor
 */
var ValidatorConfigError = function ValidatorConfigError(error)
{
  if (error) {
    error.__proto__ = ValidatorConfigError.prototype;
    return error;
  }
}

ValidatorConfigError.prototype = new Error();
ValidatorConfigError.prototype.name = "ValidatorConfigError";

exports.ValidatorConfigError = ValidatorConfigError;
