/**
 * This file contains utilities to help encode and decode NDN objects.
 * Copyright (C) 2013-2014 Regents of the University of California.
 * author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
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
    if (data.name != null && data.name.components != null) {
      output+= "NAME: " + data.name.toUri();
        
      output+= "<br />";
      output+= "<br />";
    }
    if (data.content != null) {
      output += "CONTENT(ASCII): "+ DataUtils.toString(data.content);
      
      output+= "<br />";
      output+= "<br />";
    }
    if (data.content != null) {
      output += "CONTENT(hex): "+ DataUtils.toHex(data.content);
      
      output+= "<br />";
      output+= "<br />";
    }
    if (data.signature != null && data.signature.digestAlgorithm != null) {
      output += "DigestAlgorithm (hex): "+ DataUtils.toHex(data.signature.digestAlgorithm);
      
      output+= "<br />";
      output+= "<br />";
    }
    if (data.signature != null && data.signature.witness != null) {
      output += "Witness (hex): "+ DataUtils.toHex(data.signature.witness);
      
      output+= "<br />";
      output+= "<br />";
    }
    if (data.signature != null && data.signature.signature != null) {
      output += "Signature(hex): "+ DataUtils.toHex(data.signature.signature);
      
      output+= "<br />";
      output+= "<br />";
    }
    if (data.signedInfo != null && data.signedInfo.publisher != null && data.signedInfo.publisher.publisherPublicKeyDigest != null) {
      output += "Publisher Public Key Digest(hex): "+ DataUtils.toHex(data.signedInfo.publisher.publisherPublicKeyDigest);
      
      output+= "<br />";
      output+= "<br />";
    }
    if (data.signedInfo != null && data.signedInfo.timestamp != null) {
      var d = new Date();
      d.setTime(data.signedInfo.timestamp.msec);
      
      var bytes = [217, 185, 12, 225, 217, 185, 12, 225];
      
      output += "TimeStamp: "+d;
      output+= "<br />";
      output += "TimeStamp(number): "+ data.signedInfo.timestamp.msec;
      
      output+= "<br />";
    }
    if (data.signedInfo != null && data.signedInfo.finalBlockID != null) {
      output += "FinalBlockID: "+ DataUtils.toHex(data.signedInfo.finalBlockID);
      output+= "<br />";
    }
    if (data.signedInfo != null && data.signedInfo.locator != null && data.signedInfo.locator.type) {
      output += "keyLocator: ";
      if (data.signedInfo.locator.type == KeyLocatorType.KEY)
        output += "Key: " + DataUtils.toHex(data.signedInfo.locator.publicKey).toLowerCase() + "<br />";
      else if (data.signedInfo.locator.type == KeyLocatorType.KEY_LOCATOR_DIGEST)
        output += "KeyLocatorDigest: " + DataUtils.toHex(data.signedInfo.locator.getKeyData()).toLowerCase() + "<br />";
      else if (data.signedInfo.locator.type == KeyLocatorType.CERTIFICATE)
        output += "Certificate: " + DataUtils.toHex(data.signedInfo.locator.certificate).toLowerCase() + "<br />";
      else if (data.signedInfo.locator.type == KeyLocatorType.KEYNAME)
        output += "KeyName: " + data.signedInfo.locator.keyName.contentName.to_uri() + "<br />";
      else
        output += "[unrecognized ndn_KeyLocatorType " + data.signedInfo.locator.type + "]<br />";      
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
