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

/** @ignore */
var Data = require('../../data.js').Data; /** @ignore */
var Name = require('../../name.js').Name; /** @ignore */
var SecurityException = require('../../security//security-exception.js').SecurityException; /** @ignore */
var Certificate = require('./certificate.js').Certificate; /** @ignore */
var WireFormat = require('../../encoding/wire-format.js').WireFormat;

/**
 * @constructor
 */
var IdentityCertificate = function IdentityCertificate(data)
{
  // Call the base constructor.
  if (data != undefined)
    // This works if data is Data or IdentityCertificate.
    Certificate.call(this, data);
  else
    Certificate.call(this);

  this.publicKeyName = new Name();

  if (data instanceof IdentityCertificate) {
    // The copy constructor.
    this.publicKeyName = new Name(data.publicKeyName);
  }
  else if (data instanceof Data) {
    if (!IdentityCertificate.isCorrectName(data.getName()))
      throw new SecurityException(new Error("Wrong Identity Certificate Name!"));

    this.setPublicKeyName();
  }
};
IdentityCertificate.prototype = new Certificate();
IdentityCertificate.prototype.name = "IdentityCertificate";

exports.IdentityCertificate = IdentityCertificate;

/**
 * Override the base class method to check that the name is a valid identity
 * certificate name.
 * @param {Name} name The identity certificate name which is copied.
 * @return {Data} This Data so that you can chain calls to update values.
 */
IdentityCertificate.prototype.setName = function(name)
{
  if (!IdentityCertificate.isCorrectName(name))
    throw new SecurityException(new Error("Wrong Identity Certificate Name!"));

  // Call the super class method.
  Certificate.prototype.setName.call(this, name);
  this.setPublicKeyName();
  return this;
};

/**
 * Override to call the base class wireDecode then update the public key name.
 * @param {Blob|Buffer} input The buffer with the bytes to decode.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to decode
 * this object. If omitted, use WireFormat.getDefaultWireFormat().
 */
IdentityCertificate.prototype.wireDecode = function(input, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());

  Certificate.prototype.wireDecode.call(this, input, wireFormat);
  this.setPublicKeyName();
};

IdentityCertificate.prototype.getPublicKeyName = function()
{
  return this.publicKeyName;
};

IdentityCertificate.isIdentityCertificate = function(certificate)
{
  return IdentityCertificate.isCorrectName(certificate.getName());
};

/**
 * Get the public key name from the full certificate name.
 * @param {Name} certificateName The full certificate name.
 * @return {Name} The related public key name.
 */
IdentityCertificate.certificateNameToPublicKeyName = function(certificateName)
{
  var idString = "ID-CERT";
  var foundIdString = false;
  var idCertComponentIndex = certificateName.size() - 1;
  for (; idCertComponentIndex + 1 > 0; --idCertComponentIndex) {
    if (certificateName.get(idCertComponentIndex).toEscapedString() == idString) {
      foundIdString = true;
      break;
    }
  }

  if (!foundIdString)
    throw new Error
      ("Incorrect identity certificate name " + certificateName.toUri());

  var tempName = certificateName.getSubName(0, idCertComponentIndex);
  var keyString = "KEY";
  var foundKeyString = false;
  var keyComponentIndex = 0;
  for (; keyComponentIndex < tempName.size(); keyComponentIndex++) {
    if (tempName.get(keyComponentIndex).toEscapedString() == keyString) {
      foundKeyString = true;
      break;
    }
  }

  if (!foundKeyString)
    throw new Error
      ("Incorrect identity certificate name " + certificateName.toUri());

  return tempName
    .getSubName(0, keyComponentIndex)
    .append(tempName.getSubName
            (keyComponentIndex + 1, tempName.size() - keyComponentIndex - 1));
};

IdentityCertificate.isCorrectName = function(name)
{
  var i = name.size() - 1;

  var idString = "ID-CERT";
  for (; i >= 0; i--) {
    if (name.get(i).toEscapedString() == idString)
      break;
  }

  if (i < 0)
    return false;

  var keyIdx = 0;
  var keyString = "KEY";
  for (; keyIdx < name.size(); keyIdx++) {
    if(name.get(keyIdx).toEscapedString() == keyString)
      break;
  }

  if (keyIdx >= name.size())
    return false;

  return true;
};

IdentityCertificate.prototype.setPublicKeyName = function()
{
  this.publicKeyName = IdentityCertificate.certificateNameToPublicKeyName
    (this.getName());
};

