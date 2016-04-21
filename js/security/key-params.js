/**
 * Copyright (C) 2014-2016 Regents of the University of California.
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

/** @ignore */
var KeyType = require('./security-types.js').KeyType;

/**
 * KeyParams is a base class for key parameters. Its subclasses are used to
 * store parameters for key generation. You should create one of the subclasses,
 * for example RsaKeyParams.
 * @constructor
 */
var KeyParams = function KeyParams(keyType)
{
  this.keyType = keyType;
};

exports.KeyParams = KeyParams;

KeyParams.prototype.getKeyType = function()
{
  return this.keyType;
};

var RsaKeyParams = function RsaKeyParams(size)
{
  // Call the base constructor.
  KeyParams.call(this, RsaKeyParams.getType());

  if (size == null)
    size = RsaKeyParams.getDefaultSize();
  this.size = size;
};

RsaKeyParams.prototype = new KeyParams();
RsaKeyParams.prototype.name = "RsaKeyParams";

exports.RsaKeyParams = RsaKeyParams;

RsaKeyParams.prototype.getKeySize = function()
{
  return this.size;
};

RsaKeyParams.getDefaultSize = function() { return 2048; };

RsaKeyParams.getType = function() { return KeyType.RSA; };

var EcdsaKeyParams = function EcdsaKeyParams(size)
{
  // Call the base constructor.
  KeyParams.call(this, EcdsaKeyParams.getType());

  if (size == null)
    size = EcdsaKeyParams.getDefaultSize();
  this.size = size;
};

EcdsaKeyParams.prototype = new KeyParams();
EcdsaKeyParams.prototype.name = "EcdsaKeyParams";

exports.EcdsaKeyParams = EcdsaKeyParams;

EcdsaKeyParams.prototype.getKeySize = function()
{
  return this.size;
};

EcdsaKeyParams.getDefaultSize = function() { return 256; };

EcdsaKeyParams.getType = function() { return KeyType.ECDSA; };

var AesKeyParams = function AesKeyParams(size)
{
  // Call the base constructor.
  KeyParams.call(this, AesKeyParams.getType());

  if (size == null)
    size = AesKeyParams.getDefaultSize();
  this.size = size;
};

AesKeyParams.prototype = new KeyParams();
AesKeyParams.prototype.name = "AesKeyParams";

exports.AesKeyParams = AesKeyParams;

AesKeyParams.prototype.getKeySize = function()
{
  return this.size;
};

AesKeyParams.getDefaultSize = function() { return 64; };

AesKeyParams.getType = function() { return KeyType.AES; };
