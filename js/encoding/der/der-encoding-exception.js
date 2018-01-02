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
 * Create a new DerEncodingException wrapping the given error object.
 * Call with: throw new DerEncodingException(new Error("message")).
 * @constructor
 * @param {Error} error The exception created with new Error.
 */
function DerEncodingException(error)
{
  if (error) {
    error.__proto__ = DerEncodingException.prototype;
    return error;
  }
}
DerEncodingException.prototype = new Error();
DerEncodingException.prototype.name = "DerEncodingException";

exports.DerEncodingException = DerEncodingException;
