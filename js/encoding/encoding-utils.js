/**
 * This file contains utilities to help encode and decode NDN objects.
 * Copyright (C) 2013-2015 Regents of the University of California.
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

var DataUtils = require('./data-utils.js').DataUtils;
var BinaryXMLEncoder = require('./binary-xml-encoder.js').BinaryXMLEncoder;
var BinaryXMLDecoder = require('./binary-xml-decoder.js').BinaryXMLDecoder;
var Key = require('../key.js').Key;
var KeyLocatorType = require('../key-locator.js').KeyLocatorType;
var Interest = require('../interest.js').Interest;
var Data = require('../data.js').Data;
var FaceInstance = require('../face-instance.js').FaceInstance;
var ForwardingEntry = require('../forwarding-entry.js').ForwardingEntry;
var WireFormat = require('./wire-format.js').WireFormat;
var LOG = require('../log.js').Log.LOG;

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

/**
 * @deprecated Use EncodingUtils.encodeToHexData(data).
 */
EncodingUtils.encodeToHexContentObject = function(data, wireFormat)
{
  return EncodingUtils.encodeToHexData(data, wireFormat);
}

EncodingUtils.encodeForwardingEntry = function(data)
{
  var enc = new BinaryXMLEncoder();
  data.to_ndnb(enc);
  var bytes = enc.getReducedOstream();

  return bytes;
};

EncodingUtils.decodeHexFaceInstance = function(result)
{
  var numbers = DataUtils.toNumbers(result);
  var decoder = new BinaryXMLDecoder(numbers);

  if (LOG > 3) console.log('DECODING HEX FACE INSTANCE  \n'+numbers);

  var faceInstance = new FaceInstance();
  faceInstance.from_ndnb(decoder);

  return faceInstance;
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
 * @deprecated Use EncodingUtils.decodeHexData(input).
 */
EncodingUtils.decodeHexContentObject = function(input, wireFormat)
{
  return EncodingUtils.decodeHexData(input, wireFormat);
}

EncodingUtils.decodeHexForwardingEntry = function(result)
{
  var numbers = DataUtils.toNumbers(result);
  var decoder = new BinaryXMLDecoder(numbers);

  if (LOG > 3) console.log('DECODED HEX FORWARDING ENTRY \n'+numbers);

  var forwardingEntry = new ForwardingEntry();
  forwardingEntry.from_ndnb(decoder);
  return forwardingEntry;
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
 * This also outputs to console.log.
 */
EncodingUtils.dataToHtml = function(/* Data */ data)
{
  var output ="";

  if (data == -1)
    output+= "NO CONTENT FOUND"
  else if (data == -2)
    output+= "CONTENT NAME IS EMPTY"
  else {
    if (data.getName() != null) {
      output+= "NAME: " + data.getName().toUri();

      output+= "<br />";
      output+= "<br />";
    }
    if (!data.getContent().isNull()) {
      output += "CONTENT(ASCII): "+ DataUtils.toString(data.getContent().buf());

      output+= "<br />";
      output+= "<br />";
    }
    if (!data.getContent().isNull()) {
      output += "CONTENT(hex): "+ data.getContent().toHex();

      output+= "<br />";
      output+= "<br />";
    }
    if (data.getSignature() != null && data.getSignature().getSignature() != null) {
      output += "Signature(hex): "+ data.getSignature().getSignature().toHex();

      output+= "<br />";
      output+= "<br />";
    }
    if (data.getMetaInfo() != null && data.getMetaInfo().getFinalBlockId().getValue().size() > 0) {
      output += "FinalBlockId: "+ data.getMetaInfo().getFinalBlockId().getValue().toHex();
      output+= "<br />";
    }
    if (data.getMetaInfo() != null && data.getMetaInfo().locator != null && data.getMetaInfo().locator.getType()) {
      output += "keyLocator: ";
      if (data.getMetaInfo().locator.getType() == KeyLocatorType.CERTIFICATE)
        output += "Certificate: " + DataUtils.toHex(data.getMetaInfo().locator.certificate).toLowerCase() + "<br />";
      else if (data.getMetaInfo().locator.getType() == KeyLocatorType.KEYNAME)
        output += "KeyName: " + data.getMetaInfo().locator.keyName.contentName.to_uri() + "<br />";
      else
        output += "[unrecognized ndn_KeyLocatorType " + data.getMetaInfo().locator.getType() + "]<br />";
    }
  }

  return output;
};

/**
 * @deprecated Use return EncodingUtils.dataToHtml(data).
 */
EncodingUtils.contentObjectToHtml = function(data)
{
  return EncodingUtils.dataToHtml(data);
}

//
// Deprecated: For the browser, define these in the global scope.  Applications should access as member of EncodingUtils.
//

var encodeToHexInterest = function(interest) { return EncodingUtils.encodeToHexInterest(interest); }
var encodeToHexContentObject = function(data) { return EncodingUtils.encodeToHexData(data); }
var encodeForwardingEntry = function(data) { return EncodingUtils.encodeForwardingEntry(data); }
var decodeHexFaceInstance = function(input) { return EncodingUtils.decodeHexFaceInstance(input); }
var decodeHexInterest = function(input) { return EncodingUtils.decodeHexInterest(input); }
var decodeHexContentObject = function(input) { return EncodingUtils.decodeHexData(input); }
var decodeHexForwardingEntry = function(input) { return EncodingUtils.decodeHexForwardingEntry(input); }
var decodeSubjectPublicKeyInfo = function(input) { return EncodingUtils.decodeSubjectPublicKeyInfo(input); }
var contentObjectToHtml = function(data) { return EncodingUtils.dataToHtml(data); }

/**
 * @deprecated Use interest.wireEncode().
 */
function encodeToBinaryInterest(interest) { return interest.wireEncode().buf(); }
/**
 * @deprecated Use data.wireEncode().
 */
function encodeToBinaryContentObject(data) { return data.wireEncode().buf(); }
