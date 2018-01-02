/**
 * Copyright (C) 2014-2018 Regents of the University of California.
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

/**
 * Create a new SecurityException to report an exception from the security
 * library, wrapping the given error object.
 * Call with: throw new SecurityException(new Error("message")).
 * @constructor
 * @param {Error} error The exception created with new Error.
 */
function SecurityException(error)
{
  if (error) {
    error.__proto__ = SecurityException.prototype;
    return error;
  }
}

SecurityException.prototype = new Error();
SecurityException.prototype.name = "SecurityException";

exports.SecurityException = SecurityException;

function UnrecognizedKeyFormatException(error)
{
  // Call the base constructor.
  SecurityException.call(this, error);
}
UnrecognizedKeyFormatException.prototype = new SecurityException();
UnrecognizedKeyFormatException.prototype.name = "UnrecognizedKeyFormatException";

exports.UnrecognizedKeyFormatException = UnrecognizedKeyFormatException;

function UnrecognizedDigestAlgorithmException(error)
{
  // Call the base constructor.
  SecurityException.call(this, error);
}
UnrecognizedDigestAlgorithmException.prototype = new SecurityException();
UnrecognizedDigestAlgorithmException.prototype.name = "UnrecognizedDigestAlgorithmException";

exports.UnrecognizedDigestAlgorithmException = UnrecognizedDigestAlgorithmException;

/**
 * Create a new InvalidArgumentException to report invalid or inconsistent
 * arguments.
 * Call with: throw new InvalidArgumentException(new Error("message")).
 * @constructor
 * @param {Error} error The exception created with new Error.
 */
function InvalidArgumentException(error)
{
  if (error) {
    error.__proto__ = InvalidArgumentException.prototype;
    return error;
  }
}

InvalidArgumentException.prototype = new Error();
InvalidArgumentException.prototype.name = "InvalidArgumentException";

exports.InvalidArgumentException = InvalidArgumentException;
