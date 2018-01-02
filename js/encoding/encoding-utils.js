/**
 * This file contains utilities to help encode and decode NDN objects.
 * Copyright (C) 2013-2018 Regents of the University of California.
 * author: Meki Cheraoui
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
var DataUtils = require('./data-utils.js').DataUtils; /** @ignore */
var KeyLocatorType = require('../key-locator.js').KeyLocatorType; /** @ignore */
var Interest = require('../interest.js').Interest; /** @ignore */
var Data = require('../data.js').Data; /** @ignore */
var Sha256WithRsaSignature = require('../sha256-with-rsa-signature.js').Sha256WithRsaSignature; /** @ignore */
var Sha256WithEcdsaSignature = require('../sha256-with-ecdsa-signature.js').Sha256WithEcdsaSignature; /** @ignore */
var HmacWithSha256Signature = require('../hmac-with-sha256-signature.js').HmacWithSha256Signature; /** @ignore */
var DigestSha256Signature = require('../digest-sha256-signature.js').DigestSha256Signature; /** @ignore */
var ContentType = require('../meta-info.js').ContentType; /** @ignore */
var WireFormat = require('./wire-format.js').WireFormat;

/**
 * An EncodingUtils has static methods for encoding data.
 * @constructor
 */
var EncodingUtils = function EncodingUtils()
{
};

exports.EncodingUtils = EncodingUtils;

EncodingUtils.encodeToHexInterest = function(interest, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  return DataUtils.toHex(interest.wireEncode(wireFormat).buf());
};

EncodingUtils.encodeToHexData = function(data, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  return DataUtils.toHex(data.wireEncode(wireFormat).buf());
};

EncodingUtils.decodeHexInterest = function(input, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  var interest = new Interest();
  interest.wireDecode(DataUtils.toNumbers(input), wireFormat);
  return interest;
};

EncodingUtils.decodeHexData = function(input, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  var data = new Data();
  data.wireDecode(DataUtils.toNumbers(input), wireFormat);
  return data;
};

/**
 * Decode the Buffer array which holds SubjectPublicKeyInfo and return an RSAKey.
 */
EncodingUtils.decodeSubjectPublicKeyInfo = function(array)
{
  var hex = DataUtils.toHex(array).toLowerCase();
  var a = _x509_getPublicKeyHexArrayFromCertHex(hex, _x509_getSubjectPublicKeyPosFromCertHex(hex, 0));
  var rsaKey = new RSAKey();
  rsaKey.setPublic(a[0], a[1]);
  return rsaKey;
}

/**
 * Return a user friendly HTML string with the contents of data.
 */
EncodingUtils.dataToHtml = function(/* Data */ data)
{
  if (data == -1)
    return "NO CONTENT FOUND";
  if (data == -2)
    return "CONTENT NAME IS EMPTY";

  var output = "";
  function append(message) {
    message = message.replace(/&/g, "&amp;");
    message = message.replace(/</g, "&lt;");

    output += message;
    output += "<br/>";
  }

  // Imitate dumpData in examples/node/test-encode-decode-data.js

  append("name: " + data.getName().toUri());
  if (data.getContent().size() > 0) {
    append("content (raw): " + data.getContent().buf().toString('binary'));
    append("content (hex): " + data.getContent().toHex());
  }
  else
    append("content: <empty>");

  if (!(data.getMetaInfo().getType() == ContentType.BLOB)) {
    if (data.getMetaInfo().getType() == ContentType.KEY)
      append("metaInfo.type: KEY");
    else if (data.getMetaInfo().getType() == ContentType.LINK)
      append("metaInfo.type: LINK");
    else if (data.getMetaInfo().getType() == ContentType.NACK)
      append("metaInfo.type: NACK");
    else if (data.getMetaInfo().getType() == ContentType.OTHER_CODE)
      append("metaInfo.type: other code " + data.getMetaInfo().getOtherTypeCode());
  }
  append("metaInfo.freshnessPeriod (milliseconds): " +
    (data.getMetaInfo().getFreshnessPeriod() >= 0 ?
      "" + data.getMetaInfo().getFreshnessPeriod() : "<none>"));
  append("metaInfo.finalBlockId: " +
    (data.getMetaInfo().getFinalBlockId().getValue().size() > 0 ?
     data.getMetaInfo().getFinalBlockId().getValue().toHex() : "<none>"));

  var keyLocator = null;
  var signature = data.getSignature();
  if (signature instanceof Sha256WithRsaSignature) {
    var signature = data.getSignature();
    append("Sha256WithRsa signature.signature: " +
      (signature.getSignature().size() > 0 ?
       signature.getSignature().toHex() : "<none>"));
    keyLocator = signature.getKeyLocator();
  }
  else if (signature instanceof Sha256WithEcdsaSignature) {
    var signature = data.getSignature();
    append("Sha256WithEcdsa signature.signature: " +
      (signature.getSignature().size() > 0 ?
       signature.getSignature().toHex() : "<none>"));
    keyLocator = signature.getKeyLocator();
  }
  else if (signature instanceof HmacWithSha256Signature) {
    var signature = data.getSignature();
    append("HmacWithSha256 signature.signature: " +
      (signature.getSignature().size() > 0 ?
       signature.getSignature().toHex() : "<none>"));
    keyLocator = signature.getKeyLocator();
  }
  else if (signature instanceof DigestSha256Signature) {
    var signature = data.getSignature();
    append("DigestSha256 signature.signature: " +
      (signature.getSignature().size() > 0 ?
       signature.getSignature().toHex() : "<none>"));
  }
  if (keyLocator !== null) {
    if (keyLocator.getType() == null)
      append("signature.keyLocator: <none>");
    else if (keyLocator.getType() == KeyLocatorType.KEY_LOCATOR_DIGEST)
      append("signature.keyLocator: KeyLocatorDigest: " + keyLocator.getKeyData().toHex());
    else if (keyLocator.getType() == KeyLocatorType.KEYNAME)
      append("signature.keyLocator: KeyName: " + keyLocator.getKeyName().toUri());
    else
      append("signature.keyLocator: <unrecognized ndn_KeyLocatorType>");
  }

  return output;
};

//
// Deprecated: For the browser, define these in the global scope.  Applications should access as member of EncodingUtils.
//

var encodeToHexInterest = function(interest) { return EncodingUtils.encodeToHexInterest(interest); }
var decodeHexInterest = function(input) { return EncodingUtils.decodeHexInterest(input); }
var decodeSubjectPublicKeyInfo = function(input) { return EncodingUtils.decodeSubjectPublicKeyInfo(input); }

/**
 * @deprecated Use interest.wireEncode().
 */
function encodeToBinaryInterest(interest) { return interest.wireEncode().buf(); }
