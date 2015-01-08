/**
 * This class is used to decode ndnb binary elements (blob, type/value pairs).
 *
 * Copyright (C) 2013-2015 Regents of the University of California.
 * @author: Meki Cheraoui
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

var NDNProtocolDTags = require('../util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var NDNTime = require('../util/ndn-time.js').NDNTime;
var DataUtils = require('./data-utils.js').DataUtils;
var DecodingException = require('./decoding-exception.js').DecodingException;
var LOG = require('../log.js').Log.LOG;

var XML_EXT = 0x00;

var XML_TAG = 0x01;

var XML_DTAG = 0x02;

var XML_ATTR = 0x03;

var XML_DATTR = 0x04;

var XML_BLOB = 0x05;

var XML_UDATA = 0x06;

var XML_CLOSE = 0x0;

var XML_SUBTYPE_PROCESSING_INSTRUCTIONS = 16;


var XML_TT_BITS = 3;
var XML_TT_MASK = ((1 << XML_TT_BITS) - 1);
var XML_TT_VAL_BITS = XML_TT_BITS + 1;
var XML_TT_VAL_MASK = ((1 << (XML_TT_VAL_BITS)) - 1);
var XML_REG_VAL_BITS = 7;
var XML_REG_VAL_MASK = ((1 << XML_REG_VAL_BITS) - 1);
var XML_TT_NO_MORE = (1 << XML_REG_VAL_BITS); // 0x80
var BYTE_MASK = 0xFF;
var LONG_BYTES = 8;
var LONG_BITS = 64;

var bits_11 = 0x0000007FF;
var bits_18 = 0x00003FFFF;
var bits_32 = 0x0FFFFFFFF;



//returns a string
tagToString = function(/*long*/ tagVal)
{
  if (tagVal >= 0 && tagVal < NDNProtocolDTagsStrings.length) {
    return NDNProtocolDTagsStrings[tagVal];
  }
  else if (tagVal == NDNProtocolDTags.NDNProtocolDataUnit) {
    return NDNProtocolDTags.NDNPROTOCOL_DATA_UNIT;
  }

  return null;
};

//returns a Long
stringToTag =  function(/*String*/ tagName)
{
  // the slow way, but right now we don't care.... want a static lookup for the forward direction
  for (var i=0; i < NDNProtocolDTagsStrings.length; ++i) {
    if (null != NDNProtocolDTagsStrings[i] && NDNProtocolDTagsStrings[i] == tagName)
      return i;
  }
  if (NDNProtocolDTags.NDNPROTOCOL_DATA_UNIT == tagName) {
    return NDNProtocolDTags.NDNProtocolDataUnit;
  }

  return null;
};

/**
 * @constructor
 */
var BinaryXMLDecoder = function BinaryXMLDecoder(input)
{
  var MARK_LEN=512;
  var DEBUG_MAX_LEN =  32768;

  this.input = input;
  this.offset = 0;
  // peekDTag sets and checks this, and readElementStartDTag uses it to avoid reading again.
  this.previouslyPeekedDTagStartOffset = -1;
};

exports.BinaryXMLDecoder = BinaryXMLDecoder;

/**
 * Decode the header from the input starting at its position, expecting the type to be DTAG and the value to be expectedTag.
   * Update the input's offset.
 * @param {number} expectedTag The expected value for DTAG.
 */
BinaryXMLDecoder.prototype.readElementStartDTag = function(expectedTag)
{
  if (this.offset == this.previouslyPeekedDTagStartOffset) {
    // peekDTag already decoded this DTag.
    if (this.previouslyPeekedDTag != expectedTag)
      throw new DecodingException(new Error("Did not get the expected DTAG " + expectedTag + ", got " + this.previouslyPeekedDTag));

    // Fast forward past the header.
    this.offset = this.previouslyPeekedDTagEndOffset;
  }
  else {
    var typeAndValue = this.decodeTypeAndVal();
    if (typeAndValue == null || typeAndValue.type() != XML_DTAG)
      throw new DecodingException(new Error("Header type is not a DTAG"));

    if (typeAndValue.val() != expectedTag)
      throw new DecodingException(new Error("Expected start element: " + expectedTag + " got: " + typeAndValue.val()));
  }
};

/**
 * @deprecated Use readElementStartDTag. Binary XML string tags and attributes are not used by any NDN encodings and
 * support is not maintained in the code base.
 */
BinaryXMLDecoder.prototype.readStartElement = function(
    //String
    startTag,
    //TreeMap<String, String>
    attributes)
{
  //TypeAndVal
  var tv = this.decodeTypeAndVal();

  if (null == tv)
    throw new DecodingException(new Error("Expected start element: " + startTag + " got something not a tag."));

  //String
  var decodedTag = null;

  if (tv.type() == XML_TAG) {
    // Tag value represents length-1 as tags can never be empty.
    var valval;

    if (typeof tv.val() == 'string')
      valval = (parseInt(tv.val())) + 1;
    else
      valval = (tv.val())+ 1;

    decodedTag = this.decodeUString(valval);
  }
  else if (tv.type() == XML_DTAG)
    decodedTag = tv.val();

  if (null ==  decodedTag || decodedTag != startTag) {
    console.log('expecting '+ startTag + ' but got '+ decodedTag);
    throw new DecodingException(new Error("Expected start element: " + startTag + " got: " + decodedTag + "(" + tv.val() + ")"));
  }

  // DKS: does not read attributes out of stream if caller doesn't
  // ask for them. Should possibly peek and skip over them regardless.
  // TODO: fix this
  if (null != attributes)
    readAttributes(attributes);
};

/**
 * @deprecated Binary XML string tags and attributes are not used by any NDN encodings and support is not maintained in the code base.
 */
BinaryXMLDecoder.prototype.readAttributes = function(
  // array of [attributeName, attributeValue]
  attributes)
{
  if (null == attributes)
    return;

  try {
    // Now need to get attributes.
    //TypeAndVal
    var nextTV = this.peekTypeAndVal();

    while (null != nextTV && (XML_ATTR == nextTV.type() || XML_DATTR == nextTV.type())) {
      // Decode this attribute. First, really read the type and value.
      //this.TypeAndVal
      var thisTV = this.decodeTypeAndVal();

      //String
      var attributeName = null;
      if (XML_ATTR == thisTV.type()) {
        // Tag value represents length-1 as attribute names cannot be empty.
        var valval ;
        if (typeof thisTV.val() == 'string')
          valval = (parseInt(thisTV.val())) + 1;
        else
          valval = (thisTV.val())+ 1;

        attributeName = this.decodeUString(valval);
      }
      else if (XML_DATTR == thisTV.type()) {
        // DKS TODO are attributes same or different dictionary?
        attributeName = tagToString(thisTV.val());
        if (null == attributeName)
          throw new DecodingException(new Error("Unknown DATTR value" + thisTV.val()));
      }

      // Attribute values are always UDATA
      //String
      var attributeValue = this.decodeUString();

      attributes.push([attributeName, attributeValue]);
      nextTV = this.peekTypeAndVal();
    }
  }
  catch (e) {
    throw new DecodingException(new Error("readStartElement", e));
  }
};

/**
 * @deprecated Use peekDTag.  Binary XML string tags and attributes are not used by any NDN encodings and
 * support is not maintained in the code base.
 */
BinaryXMLDecoder.prototype.peekStartElementAsString = function()
{
  //String
  var decodedTag = null;
  var previousOffset = this.offset;
  try {
    // Have to distinguish genuine errors from wrong tags. Could either use
    // a special exception subtype, or redo the work here.
    //this.TypeAndVal
    var tv = this.decodeTypeAndVal();

    if (null != tv) {
      if (tv.type() == XML_TAG) {
        // Tag value represents length-1 as tags can never be empty.
        var valval ;
        if (typeof tv.val() == 'string')
          valval = (parseInt(tv.val())) + 1;
        else
          valval = (tv.val())+ 1;

        decodedTag = this.decodeUString(valval);
      }
      else if (tv.type() == XML_DTAG)
        decodedTag = tagToString(tv.val());
    } // else, not a type and val, probably an end element. rewind and return false.
  }
  catch (e) {
  }
  finally {
    try {
      this.offset = previousOffset;
    }
    catch (e) {
      Log.logStackTrace(Log.FAC_ENCODING, Level.WARNING, e);
      throw new DecodingException(new Error("Cannot reset stream! " + e.getMessage(), e));
    }
  }

  return decodedTag;
};

/**
 * Decode the header from the input starting at its position, and if it is a DTAG where the value is the expectedTag,
 * then set return true.  Do not update the input's offset.
 * @param {number} expectedTag The expected value for DTAG.
 * @returns {boolean} True if the tag is the expected tag, otherwise false.
 */
BinaryXMLDecoder.prototype.peekDTag = function(expectedTag)
{
  if (this.offset == this.previouslyPeekedDTagStartOffset)
    // We already decoded this DTag.
    return this.previouslyPeekedDTag == expectedTag;
  else {
    // First check if it is an element close (which cannot be the expected tag).
    if (this.input[this.offset] == XML_CLOSE)
      return false;

    var saveOffset = this.offset;
    var typeAndValue = this.decodeTypeAndVal();
    // readElementStartDTag will use this to fast forward.
    this.previouslyPeekedDTagEndOffset = this.offset;
    // Restore the position.
    this.offset = saveOffset;

    if (typeAndValue != null && typeAndValue.type() == XML_DTAG) {
      this.previouslyPeekedDTagStartOffset = saveOffset;
      this.previouslyPeekedDTag = typeAndValue.val();

      return typeAndValue.val() == expectedTag;
    }
    else
      return false;
  }
};

/**
 * @deprecated Use peekDTag.  Binary XML string tags and attributes are not used by any NDN encodings and
 * support is not maintained in the code base.
 */
BinaryXMLDecoder.prototype.peekStartElement = function(
    //String
    startTag)
{
  //String
  if (typeof startTag == 'string') {
    var decodedTag = this.peekStartElementAsString();

    if (null !=  decodedTag && decodedTag == startTag)
      return true;

    return false;
  }
  else if (typeof startTag == 'number') {
    var decodedTag = this.peekStartElementAsLong();
    if (null !=  decodedTag && decodedTag == startTag)
      return true;

    return false;
  }
  else
    throw new DecodingException(new Error("SHOULD BE STRING OR NUMBER"));
};

/**
 * @deprecated Use peekDTag.  Binary XML string tags and attributes are not used by any NDN encodings and
 * support is not maintained in the code base.
 */
BinaryXMLDecoder.prototype.peekStartElementAsLong = function()
{
  //Long
  var decodedTag = null;
  var previousOffset = this.offset;

  try {
    // Have to distinguish genuine errors from wrong tags. Could either use
    // a special exception subtype, or redo the work here.
    //this.TypeAndVal
    var tv = this.decodeTypeAndVal();

    if (null != tv) {
      if (tv.type() == XML_TAG) {
        if (tv.val() + 1 > DEBUG_MAX_LEN)
          throw new DecodingException(new Error("Decoding error: length " + tv.val()+1 + " longer than expected maximum length!"));

        var valval;
        if (typeof tv.val() == 'string')
          valval = (parseInt(tv.val())) + 1;
        else
          valval = (tv.val())+ 1;

        // Tag value represents length-1 as tags can never be empty.
        //String
        var strTag = this.decodeUString(valval);

        decodedTag = stringToTag(strTag);
      }
      else if (tv.type() == XML_DTAG)
        decodedTag = tv.val();
    } // else, not a type and val, probably an end element. rewind and return false.

  }
  catch (e) {
  }
  finally {
    try {
      //this.input.reset();
      this.offset = previousOffset;
    } catch (e) {
      Log.logStackTrace(Log.FAC_ENCODING, Level.WARNING, e);
      throw new Error("Cannot reset stream! " + e.getMessage(), e);
    }
  }

  return decodedTag;
};

/**
 * Decode the header from the input starting its offset, expecting the type to be DTAG and the value to be expectedTag.
 * Then read one item of any type (presumably BLOB, UDATA, TAG or ATTR) and return a
 * Buffer. However, if allowNull is true, then the item may be absent.
 * Finally, read the element close.  Update the input's offset.
 * @param {number} expectedTag The expected value for DTAG.
 * @param {boolean} allowNull True if the binary item may be missing.
 * @returns {Buffer} A Buffer which is a slice on the data inside the input buffer. However,
 * if allowNull is true and the binary data item is absent, then return null.
 */
BinaryXMLDecoder.prototype.readBinaryDTagElement = function(expectedTag, allowNull)
{
  this.readElementStartDTag(expectedTag);
  return this.readBlob(allowNull);
};

/**
 * @deprecated Use readBinaryDTagElement.  Binary XML string tags and attributes are not used by any NDN encodings and
 * support is not maintained in the code base.
 */
BinaryXMLDecoder.prototype.readBinaryElement = function(
    //long
    startTag,
    //TreeMap<String, String>
    attributes,
    //boolean
    allowNull)
{
  this.readStartElement(startTag, attributes);
  return this.readBlob(allowNull);
};

/**
 * Read one byte from the input starting at its offset, expecting it to be the element close.
 * Update the input's offset.
 */
BinaryXMLDecoder.prototype.readElementClose = function()
{
  var next = this.input[this.offset++];
  if (next != XML_CLOSE)
    throw new DecodingException(new Error("Expected end element, got: " + next));
};

/**
 * @deprecated Use readElementClose.
 */
BinaryXMLDecoder.prototype.readEndElement = function()
{
  if (LOG > 4) console.log('this.offset is '+this.offset);

  var next = this.input[this.offset];

  this.offset++;

  if (LOG > 4) console.log('XML_CLOSE IS '+XML_CLOSE);
  if (LOG > 4) console.log('next is '+next);

  if (next != XML_CLOSE) {
    console.log("Expected end element, got: " + next);
    throw new DecodingException(new Error("Expected end element, got: " + next));
  }
};

//String
BinaryXMLDecoder.prototype.readUString = function()
{
  //String
  var ustring = this.decodeUString();
  this.readElementClose();
  return ustring;
};

/**
 * Read a blob as well as the end element. Returns a Buffer (or null for missing blob).
 * If the blob is missing and allowNull is false (default), throw an exception.  Otherwise,
 *   just read the end element and return null.
 */
BinaryXMLDecoder.prototype.readBlob = function(allowNull)
{
  if (this.input[this.offset] == XML_CLOSE && allowNull) {
    this.readElementClose();
    return null;
  }

  var blob = this.decodeBlob();
  this.readElementClose();
  return blob;
};

/**
 * Decode the header from the input starting at its offset, expecting the type to be
 * DTAG and the value to be expectedTag.  Then read one item, parse it as an unsigned
 * big endian integer in 4096 ticks per second, and convert it to and NDNTime object.
 * Finally, read the element close.  Update the input's offset.
 * @param {number} expectedTag The expected value for DTAG.
 * @returns {NDNTime} The dateTime value.
 */
BinaryXMLDecoder.prototype.readDateTimeDTagElement = function(expectedTag)
{
  var byteTimestamp = this.readBinaryDTagElement(expectedTag);
  byteTimestamp = DataUtils.toHex(byteTimestamp);
  byteTimestamp = parseInt(byteTimestamp, 16);

  var lontimestamp = (byteTimestamp/ 4096) * 1000;

  var timestamp = new NDNTime(lontimestamp);
  if (null == timestamp)
    throw new DecodingException(new Error("Cannot parse timestamp: " + DataUtils.printHexBytes(byteTimestamp)));

  return timestamp;
};

/**
 * @deprecated Use readDateTimeDTagElement.  Binary XML string tags and attributes are not used by any NDN encodings and
 * support is not maintained in the code base.
 */
BinaryXMLDecoder.prototype.readDateTime = function(
  //long
  startTag)
{
  var byteTimestamp = this.readBinaryElement(startTag);
  byteTimestamp = DataUtils.toHex(byteTimestamp);
  byteTimestamp = parseInt(byteTimestamp, 16);

  var lontimestamp = (byteTimestamp/ 4096) * 1000;

  if (LOG > 4) console.log('DECODED DATE WITH VALUE');
  if (LOG > 4) console.log(lontimestamp);

  //NDNTime
  var timestamp = new NDNTime(lontimestamp);
  if (null == timestamp)
    throw new DecodingException(new Error("Cannot parse timestamp: " + DataUtils.printHexBytes(byteTimestamp)));

  return timestamp;
};

BinaryXMLDecoder.prototype.decodeTypeAndVal = function()
{

  /*int*/ var type = -1;
  /*long*/ var val = 0;
  /*boolean*/ var more = true;

  do {
    var next = this.input[this.offset ];
    if (next == null)
      // Quit the loop.
      return null;

    if (next < 0)
      return null;

    if (0 == next && 0 == val)
      return null;

    more = (0 == (next & XML_TT_NO_MORE));

    if  (more) {
      val = val << XML_REG_VAL_BITS;
      val |= (next & XML_REG_VAL_MASK);
    }
    else {
      type = next & XML_TT_MASK;
      val = val << XML_TT_VAL_BITS;
      val |= ((next >>> XML_TT_BITS) & XML_TT_VAL_MASK);
    }

    this.offset++;
  } while (more);

  if (LOG > 4) console.log('TYPE is '+ type + ' VAL is '+ val);

  return new TypeAndVal(type, val);
};

//TypeAndVal
BinaryXMLDecoder.prototype.peekTypeAndVal = function()
{
  //TypeAndVal
  var tv = null;
  var previousOffset = this.offset;

  try {
    tv = this.decodeTypeAndVal();
  }
  finally {
    this.offset = previousOffset;
  }

  return tv;
};

//Buffer
BinaryXMLDecoder.prototype.decodeBlob = function(
    //int
    blobLength)
{
  if (null == blobLength) {
    //TypeAndVal
    var tv = this.decodeTypeAndVal();

    var valval ;
    if (typeof tv.val() == 'string')
      valval = (parseInt(tv.val()));
    else
      valval = (tv.val());

    return this.decodeBlob(valval);
  }

  //Buffer
  var bytes = new Buffer(this.input.slice(this.offset, this.offset+ blobLength));
  this.offset += blobLength;

  return bytes;
};

//String
BinaryXMLDecoder.prototype.decodeUString = function(
    //int
    byteLength)
{
  if (null == byteLength) {
    var tempStreamPosition = this.offset;

    //TypeAndVal
    var tv = this.decodeTypeAndVal();

    if (LOG > 4) console.log('TV is '+tv);
    if (LOG > 4) console.log(tv);

    if (LOG > 4) console.log('Type of TV is '+typeof tv);

    // if we just have closers left, will get back null
    if (null == tv || XML_UDATA != tv.type()) {
      this.offset = tempStreamPosition;
      return "";
    }

    return this.decodeUString(tv.val());
  }
  else {
    //Buffer
    var stringBytes = this.decodeBlob(byteLength);

    // TODO: Should this parse as UTF8?
    return DataUtils.toString(stringBytes);
  }
};

//OBject containg a pair of type and value
var TypeAndVal = function TypeAndVal(_type,_val)
{
  this.t = _type;
  this.v = _val;
};

TypeAndVal.prototype.type = function()
{
  return this.t;
};

TypeAndVal.prototype.val = function()
{
  return this.v;
};

/**
 * Decode the header from the input starting its offset, expecting the type to be DTAG and the value to be expectedTag.
 * Then read one UDATA item, parse it as a decimal integer and return the integer. Finally, read the element close.  Update the input's offset.
 * @param {number} expectedTag The expected value for DTAG.
 * @returns {number} The parsed integer.
 */
BinaryXMLDecoder.prototype.readIntegerDTagElement = function(expectedTag)
{
  return parseInt(this.readUTF8DTagElement(expectedTag));
};

/**
 * @deprecated Use readIntegerDTagElement.  Binary XML string tags and attributes are not used by any NDN encodings and
 * support is not maintained in the code base.
 */
BinaryXMLDecoder.prototype.readIntegerElement = function(
  //String
  startTag)
{
  //String
  if (LOG > 4) console.log('READING INTEGER '+ startTag);
  if (LOG > 4) console.log('TYPE OF '+ typeof startTag);

  var strVal = this.readUTF8Element(startTag);

  return parseInt(strVal);
};

/**
 * Decode the header from the input starting its offset, expecting the type to be DTAG and the value to be expectedTag.
 * Then read one UDATA item and return a string. Finally, read the element close.  Update the input's offset.
 * @param {number} expectedTag The expected value for DTAG.
 * @returns {string} The UDATA string.
 */
BinaryXMLDecoder.prototype.readUTF8DTagElement = function(expectedTag)
{
  this.readElementStartDTag(expectedTag);
  return this.readUString();;
};

/**
 * @deprecated Use readUTF8DTagElement.  Binary XML string tags and attributes are not used by any NDN encodings and
 * support is not maintained in the code base.
 */
BinaryXMLDecoder.prototype.readUTF8Element = function(
    //String
    startTag,
    //TreeMap<String, String>
    attributes)
{
  //throws Error where name == "DecodingException"

  // can't use getElementText, can't get attributes
  this.readStartElement(startTag, attributes);
  //String
  var strElementText = this.readUString();
  return strElementText;
};

/**
 * Set the offset into the input, used for the next read.
 * @param {number} offset The new offset.
 */
BinaryXMLDecoder.prototype.seek = function(offset)
{
  this.offset = offset;
};
