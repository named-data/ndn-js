/**
 * Copyright (C) 2015-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt src/error-code https://github.com/named-data/ndn-group-encrypt
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
 * EncryptError holds the ErrorCode enum for errors from the encrypt library.
 */
var EncryptError = function EncryptError()
{
};

exports.EncryptError = EncryptError;

EncryptError.ErrorCode = {
  Timeout:                     1,
  Validation:                  2,
  UnsupportedEncryptionScheme: 32,
  InvalidEncryptedFormat:      33,
  NoDecryptKey:                34,
  EncryptionFailure:           35,
  DataRetrievalFailure:        36,
  General:                     100
};
