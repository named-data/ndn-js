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
 * This module defines constants used by the security library.
 */

/**
 * The KeyType integer is used by the Sqlite key storage, so don't change them.
 * Make these the same as ndn-cxx in case the storage file is shared.
 * @constructor
 */
var KeyType = function KeyType()
{
}

exports.KeyType = KeyType;

KeyType.RSA = 0;
KeyType.EC = 1;
/**
 * @deprecated Use KeyType.EC .
 */
KeyType.ECDSA = 1;
KeyType.AES = 128;

var KeyClass = function KeyClass()
{
};

exports.KeyClass = KeyClass;

KeyClass.PUBLIC = 1;
KeyClass.PRIVATE = 2;
KeyClass.SYMMETRIC = 3;

var DigestAlgorithm = function DigestAlgorithm()
{
};

exports.DigestAlgorithm = DigestAlgorithm;

DigestAlgorithm.SHA256 = 1;
