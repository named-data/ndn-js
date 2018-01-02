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
var ContentType = require('../../meta-info.js').ContentType; /** @ignore */
var WireFormat = require('../../encoding/wire-format.js').WireFormat; /** @ignore */
var DerNode = require('../../encoding/der/der-node.js').DerNode; /** @ignore */
var KeyType = require('../../security/security-types.js').KeyType; /** @ignore */
var PublicKey = require('./public-key.js').PublicKey; /** @ignore */
var CertificateSubjectDescription = require('./certificate-subject-description.js').CertificateSubjectDescription; /** @ignore */
var CertificateExtension = require('./certificate-extension.js').CertificateExtension;

/**
 * Create a Certificate from the content in the data packet (if not omitted).
 * @param {Data} data (optional) The data packet with the content to decode.
 * If omitted, create a Certificate with default values and the Data content
 * is empty.
 * @constructor
 */
var Certificate = function Certificate(data)
{
  // Call the base constructor.
  if (data != undefined)
    Data.call(this, data);
  else
    Data.call(this);

  this.subjectDescriptionList = [];  // of CertificateSubjectDescription
  this.extensionList = [];           // of CertificateExtension
  this.notBefore = Number.MAX_VALUE; // MillisecondsSince1970
  this.notAfter = -Number.MAX_VALUE; // MillisecondsSince1970
  this.key = new PublicKey();

  if (data != undefined)
    this.decode();
};
Certificate.prototype = new Data();
Certificate.prototype.name = "Certificate";

exports.Certificate = Certificate;

/**
 * Encode the contents of the certificate in DER format and set the Content
 * and MetaInfo fields.
 */
Certificate.prototype.encode = function()
{
  var root = this.toDer();
  this.setContent(root.encode());
  this.getMetaInfo().setType(ContentType.KEY);
};

/**
 * Add a subject description.
 * @param {CertificateSubjectDescription} description The description to be added.
 */
Certificate.prototype.addSubjectDescription = function(description)
{
  this.subjectDescriptionList.push(description);
};

/**
 * Get the subject description list.
 * @return {Array<CertificateSubjectDescription>} The subject description list.
 */
Certificate.prototype.getSubjectDescriptionList = function()
{
  return this.subjectDescriptionList;
};

/**
 * Add a certificate extension.
 * @param {CertificateSubjectDescription} extension The extension to be added.
 */
Certificate.prototype.addExtension = function(extension)
{
  this.extensionList.push(extension);
};

/**
 * Get the certificate extension list.
 * @return {Array<CertificateExtension>} The extension list.
 */
Certificate.prototype.getExtensionList = function()
{
  return this.extensionList;
};

Certificate.prototype.setNotBefore = function(notBefore)
{
  this.notBefore = notBefore;
};

Certificate.prototype.getNotBefore = function()
{
  return this.notBefore;
};

Certificate.prototype.setNotAfter = function(notAfter)
{
  this.notAfter = notAfter;
};

Certificate.prototype.getNotAfter = function()
{
  return this.notAfter;
};

Certificate.prototype.setPublicKeyInfo = function(key)
{
  this.key = key;
};

Certificate.prototype.getPublicKeyInfo = function()
{
  return this.key;
};

/**
 * Get the public key DER encoding.
 * @return {Blob} The DER encoding Blob.
 * @throws Error if the public key is not set.
 */
Certificate.prototype.getPublicKeyDer = function()
{
  if (this.key.getKeyDer().isNull())
    throw new Error("The public key is not set");

  return this.key.getKeyDer();
};

/**
 * Check if the certificate is valid.
 * @return {Boolean} True if the current time is earlier than notBefore.
 */
Certificate.prototype.isTooEarly = function()
{
  var now = new Date().getTime();
  return now < this.getNotBefore();
};

/**
 * Check if the certificate is valid.
 * @return {Boolean} True if the current time is later than notAfter.
 */
Certificate.prototype.isTooLate = function()
{
  var now = new Date().getTime();
  return now > this.getNotAfter();
};

Certificate.prototype.isInValidityPeriod = function(time)
{
  return this.getSignature().getValidityPeriod().isValid(time);
};

/**
 * Encode the certificate fields in DER format.
 * @return {DerSequence} The DER encoded contents of the certificate.
 */
Certificate.prototype.toDer = function()
{
  var root = new DerNode.DerSequence();
  var validity = new DerNode.DerSequence();
  var notBefore = new DerNode.DerGeneralizedTime(this.getNotBefore());
  var notAfter = new DerNode.DerGeneralizedTime(this.getNotAfter());

  validity.addChild(notBefore);
  validity.addChild(notAfter);

  root.addChild(validity);

  var subjectList = new DerNode.DerSequence();
  for (var i = 0; i < this.subjectDescriptionList.length; ++i)
    subjectList.addChild(this.subjectDescriptionList[i].toDer());

  root.addChild(subjectList);
  root.addChild(this.key.toDer());

  if (this.extensionList.length > 0) {
    var extensionList = new DerNode.DerSequence();
    for (var i = 0; i < this.extensionList.length; ++i)
      extensionList.addChild(this.extensionList[i].toDer());
    root.addChild(extensionList);
  }

  return root;
};

/**
 * Populate the fields by the decoding DER data from the Content.
 */
Certificate.prototype.decode = function()
{
  var root = DerNode.parse(this.getContent().buf());

  // We need to ensure that there are:
  //   validity (notBefore, notAfter)
  //   subject list
  //   public key
  //   (optional) extension list

  var rootChildren = root.getChildren();
  // 1st: validity info
  var validityChildren = DerNode.getSequence(rootChildren, 0).getChildren();
  this.notBefore = validityChildren[0].toVal();
  this.notAfter = validityChildren[1].toVal();

  // 2nd: subjectList
  var subjectChildren = DerNode.getSequence(rootChildren, 1).getChildren();
  for (var i = 0; i < subjectChildren.length; ++i) {
    var sd = DerNode.getSequence(subjectChildren, i);
    var descriptionChildren = sd.getChildren();
    var oidStr = descriptionChildren[0].toVal();
    var value = descriptionChildren[1].toVal().buf().toString('binary');

    this.addSubjectDescription(new CertificateSubjectDescription(oidStr, value));
  }

  // 3rd: public key
  var publicKeyInfo = rootChildren[2].encode();
  this.key =  new PublicKey(publicKeyInfo);

  if (rootChildren.length > 3) {
    var extensionChildren = DerNode.getSequence(rootChildren, 3).getChildren();
    for (var i = 0; i < extensionChildren.length; ++i) {
      var extInfo = DerNode.getSequence(extensionChildren, i);

      var children = extInfo.getChildren();
      var oidStr = children[0].toVal();
      var isCritical = children[1].toVal();
      var value = children[2].toVal();
      this.addExtension(new CertificateExtension(oidStr, isCritical, value));
    }
  }
};

/**
 * Override to call the base class wireDecode then populate the certificate
 * fields.
 * @param {Blob|Buffer} input The buffer with the bytes to decode.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to decode
 * this object. If omitted, use WireFormat.getDefaultWireFormat().
 */
Certificate.prototype.wireDecode = function(input, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());

  Data.prototype.wireDecode.call(this, input, wireFormat);
  this.decode();
};

Certificate.prototype.toString = function()
{
  var s = "Certificate name:\n";
  s += "  " + this.getName().toUri() + "\n";
  s += "Validity:\n";

  var notBeforeStr = Certificate.toIsoString(Math.round(this.getNotBefore()));
  var notAfterStr = Certificate.toIsoString(Math.round(this.getNotAfter()));

  s += "  NotBefore: " + notBeforeStr + "\n";
  s += "  NotAfter: " + notAfterStr + "\n";
  for (var i = 0; i < this.subjectDescriptionList.length; ++i) {
    var sd = this.subjectDescriptionList[i];
    s += "Subject Description:\n";
    s += "  " + sd.getOidString() + ": " + sd.getValue() + "\n";
  }

  s += "Public key bits:\n";
  var keyDer = this.getPublicKeyDer();
  var encodedKey = keyDer.buf().toString('base64');
  for (var i = 0; i < encodedKey.length; i += 64)
    s += encodedKey.substring(i, Math.min(i + 64, encodedKey.length)) + "\n";

  if (this.extensionList.length > 0) {
    s += "Extensions:\n";
    for (var i = 0; i < this.extensionList.length; ++i) {
      var ext = this.extensionList[i];
      s += "  OID: " + ext.getOid() + "\n";
      s += "  Is critical: " + (ext.getIsCritical() ? 'Y' : 'N') + "\n";

      s += "  Value: " + ext.getValue().toHex() + "\n" ;
    }
  }

  return s;
};

/**
 * Convert a UNIX timestamp to ISO time representation with the "T" in the middle.
 * @param {type} msSince1970 Timestamp as milliseconds since Jan 1, 1970.
 * @return {string} The string representation.
 */
Certificate.toIsoString = function(msSince1970)
{
  var utcTime = new Date(Math.round(msSince1970));
  return utcTime.getUTCFullYear() +
         Certificate.to2DigitString(utcTime.getUTCMonth() + 1) +
         Certificate.to2DigitString(utcTime.getUTCDate()) +
         "T" +
         Certificate.to2DigitString(utcTime.getUTCHours()) +
         Certificate.to2DigitString(utcTime.getUTCMinutes()) +
         Certificate.to2DigitString(utcTime.getUTCSeconds());
};

/**
 * A private method to zero pad an integer to 2 digits.
 * @param {number} x The number to pad.  Assume it is a non-negative integer.
 * @return {string} The padded string.
 */
Certificate.to2DigitString = function(x)
{
  var result = x.toString();
  return result.length === 1 ? "0" + result : result;
};
