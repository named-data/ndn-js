/**
 * Copyright (C) 2015-2019 Regents of the University of California.
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
  KekRetrievalFailure:  1,
  KekRetrievalTimeout:  2,
  KekInvalidName:       3,

  KdkRetrievalFailure:  11,
  KdkRetrievalTimeout:  12,
  KdkInvalidName:       13,
  KdkDecryptionFailure: 14,

  CkRetrievalFailure:   21,
  CkRetrievalTimeout:   22,
  CkInvalidName:        23,

  MissingRequiredKeyLocator:    101,
  TpmKeyNotFound:               102,
  EncryptionFailure:            103,
  DecryptionFailure:            104,
  MissingRequiredInitialVector: 110,

  General:                      200,

  // @deprecated These codes are from the NAC library v1.
  Timeout:                     1001,
  Validation:                  1002,
  UnsupportedEncryptionScheme: 1032,
  InvalidEncryptedFormat:      1033,
  NoDecryptKey:                1034,
  DataRetrievalFailure:        1036
};
