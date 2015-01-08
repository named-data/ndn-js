/**
 * This class is used to encode ndnb binary elements (blob, type/value pairs).
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

var LOG = require('../log.js').Log.LOG;

var NDNProtocolDTags = require('../util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var DynamicBuffer = require('../util/dynamic-buffer.js').DynamicBuffer;
var DataUtils = require('./data-utils.js').DataUtils;
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

/**
 * @constructor
 */
var BinaryXMLEncoder = function BinaryXMLEncoder(initiaLength)
{
  if (!initiaLength)
    initiaLength = 16;

  this.ostream = new DynamicBuffer(initiaLength);
  this.offset = 0;
  this.CODEC_NAME = "Binary";
};

exports.BinaryXMLEncoder = BinaryXMLEncoder;

/**
 * Encode utf8Content as utf8 and write to the output buffer as a UDATA.
 * @param {string} utf8Content The string to convert to utf8.
 */
BinaryXMLEncoder.prototype.writeUString = function(utf8Content)
{
  this.encodeUString(utf8Content, XML_UDATA);
};

BinaryXMLEncoder.prototype.writeBlob = function(
    /*Buffer*/ binaryContent)
{
  if (LOG >3) console.log(binaryContent);

  this.encodeBlob(binaryContent, binaryContent.length);
};

/**
 * Write an element start header using DTAG with the tag to the output buffer.
 * @param {number} tag The DTAG tag.
 */
BinaryXMLEncoder.prototype.writeElementStartDTag = function(tag)
{
  this.encodeTypeAndVal(XML_DTAG, tag);
};

/**
 * @deprecated Use writeElementStartDTag.  Binary XML string tags and attributes are not used by any NDN encodings and
 * support is not maintained in the code base.
 */
BinaryXMLEncoder.prototype.writeStartElement = function(
  /*String*/ tag,
  /*TreeMap<String,String>*/ attributes)
{
  /*Long*/ var dictionaryVal = tag; //stringToTag(tag);

  if (null == dictionaryVal)
    this.encodeUString(tag, XML_TAG);
  else
    this.encodeTypeAndVal(XML_DTAG, dictionaryVal);

  if (null != attributes)
    this.writeAttributes(attributes);
};

/**
 * Write an element close to the output buffer.
 */
BinaryXMLEncoder.prototype.writeElementClose = function()
{
  this.ostream.ensureLength(this.offset + 1);
  this.ostream.array[this.offset] = XML_CLOSE;
  this.offset += 1;
};

/**
 * @deprecated Use writeElementClose.
 */
BinaryXMLEncoder.prototype.writeEndElement = function()
{
  this.writeElementClose();
};

/**
 * @deprecated Binary XML string tags and attributes are not used by any NDN encodings and support is not maintained in the code base.
 */
BinaryXMLEncoder.prototype.writeAttributes = function(/*TreeMap<String,String>*/ attributes)
{
  if (null == attributes)
    return;

  // the keySet of a TreeMap is sorted.

  for (var i = 0; i< attributes.length;i++) {
    var strAttr = attributes[i].k;
    var strValue = attributes[i].v;

    var dictionaryAttr = stringToTag(strAttr);
    if (null == dictionaryAttr)
      // not in dictionary, encode as attr
      // compressed format wants length of tag represented as length-1
      // to save that extra bit, as tag cannot be 0 length.
      // encodeUString knows to do that.
      this.encodeUString(strAttr, XML_ATTR);
    else
      this.encodeTypeAndVal(XML_DATTR, dictionaryAttr);

    // Write value
    this.encodeUString(strValue);
  }
};

//returns a string
stringToTag = function(/*long*/ tagVal)
{
  if (tagVal >= 0 && tagVal < NDNProtocolDTagsStrings.length)
    return NDNProtocolDTagsStrings[tagVal];
  else if (tagVal == NDNProtocolDTags.NDNProtocolDataUnit)
    return NDNProtocolDTags.NDNPROTOCOL_DATA_UNIT;

  return null;
};

//returns a Long
tagToString =  function(/*String*/ tagName)
{
  // the slow way, but right now we don't care.... want a static lookup for the forward direction
  for (var i = 0; i < NDNProtocolDTagsStrings.length; ++i) {
    if (null != NDNProtocolDTagsStrings[i] && NDNProtocolDTagsStrings[i] == tagName)
      return i;
  }

  if (NDNProtocolDTags.NDNPROTOCOL_DATA_UNIT == tagName)
    return NDNProtocolDTags.NDNProtocolDataUnit;

  return null;
};

/**
 * Write an element start header using DTAG with the tag to the output buffer, then the content as explained below,
 * then an element close.
 * @param {number} tag The DTAG tag.
 * @param {number|string|Buffer} content If contentis a number, convert it to a string and call writeUString.  If content is a string,
 * call writeUString.  Otherwise, call writeBlob.
 */
BinaryXMLEncoder.prototype.writeDTagElement = function(tag, content)
{
  this.writeElementStartDTag(tag);

  if (typeof content === 'number')
    this.writeUString(content.toString());
  else if (typeof content === 'string')
    this.writeUString(content);
  else
    this.writeBlob(content);

  this.writeElementClose();
};

/**
 * @deprecated Use writeDTagElement.  Binary XML string tags and attributes are not used by any NDN encodings and
 * support is not maintained in the code base.
 * If Content is a string, then encode as utf8 and write UDATA.
 */
BinaryXMLEncoder.prototype.writeElement = function(
    //long
    tag,
    //byte[]
    Content,
    //TreeMap<String, String>
    attributes)
{
  this.writeStartElement(tag, attributes);
  // Will omit if 0-length

  if (typeof Content === 'number') {
    if (LOG > 4) console.log('GOING TO WRITE THE NUMBER .charCodeAt(0) ' + Content.toString().charCodeAt(0));
    if (LOG > 4) console.log('GOING TO WRITE THE NUMBER ' + Content.toString());
    if (LOG > 4) console.log('type of number is ' + typeof Content.toString());

    this.writeUString(Content.toString());
  }
  else if (typeof Content === 'string') {
    if (LOG > 4) console.log('GOING TO WRITE THE STRING  ' + Content);
    if (LOG > 4) console.log('type of STRING is ' + typeof Content);

    this.writeUString(Content);
  }
  else {
    if (LOG > 4) console.log('GOING TO WRITE A BLOB  ' + Content);

    this.writeBlob(Content);
  }

  this.writeElementClose();
};

var TypeAndVal = function TypeAndVal(_type,_val)
{
  this.type = _type;
  this.val = _val;
};

BinaryXMLEncoder.prototype.encodeTypeAndVal = function(
    //int
    type,
    //long
    val)
{
  if (LOG > 4) console.log('Encoding type '+ type+ ' and value '+ val);

  if (LOG > 4) console.log('OFFSET IS ' + this.offset);

  if (type > XML_UDATA || type < 0 || val < 0)
    throw new Error("Tag and value must be positive, and tag valid.");

  // Encode backwards. Calculate how many bytes we need:
  var numEncodingBytes = this.numEncodingBytes(val);
  this.ostream.ensureLength(this.offset + numEncodingBytes);

  // Bottom 4 bits of val go in last byte with tag.
  this.ostream.array[this.offset + numEncodingBytes - 1] =
    //(byte)
      (BYTE_MASK &
          (((XML_TT_MASK & type) |
           ((XML_TT_VAL_MASK & val) << XML_TT_BITS))) |
           XML_TT_NO_MORE); // set top bit for last byte
  val = val >>> XML_TT_VAL_BITS;

  // Rest of val goes into preceding bytes, 7 bits per byte, top bit
  // is "more" flag.
  var i = this.offset + numEncodingBytes - 2;
  while (0 != val && i >= this.offset) {
    this.ostream.array[i] = //(byte)
        (BYTE_MASK & (val & XML_REG_VAL_MASK)); // leave top bit unset
    val = val >>> XML_REG_VAL_BITS;
    --i;
  }

  if (val != 0)
    throw new Error("This should not happen: miscalculated encoding");

  this.offset+= numEncodingBytes;

  return numEncodingBytes;
};

/**
 * Encode ustring as utf8.
 */
BinaryXMLEncoder.prototype.encodeUString = function(
    //String
    ustring,
    //byte
    type)
{
  if (null == ustring)
    return;
  if (type == XML_TAG || type == XML_ATTR && ustring.length == 0)
    return;

  if (LOG > 3) console.log("The string to write is ");
  if (LOG > 3) console.log(ustring);

  var strBytes = DataUtils.stringToUtf8Array(ustring);

  this.encodeTypeAndVal(type,
            (((type == XML_TAG) || (type == XML_ATTR)) ?
                (strBytes.length-1) :
                strBytes.length));

  if (LOG > 3) console.log("THE string to write is ");

  if (LOG > 3) console.log(strBytes);

  this.writeString(strBytes);
  this.offset+= strBytes.length;
};


BinaryXMLEncoder.prototype.encodeBlob = function(
    //Buffer
    blob,
    //int
    length)
{
  if (null == blob)
    return;

  if (LOG > 4) console.log('LENGTH OF XML_BLOB IS '+length);

  this.encodeTypeAndVal(XML_BLOB, length);
  this.writeBlobArray(blob);
  this.offset += length;
};

var ENCODING_LIMIT_1_BYTE = ((1 << (XML_TT_VAL_BITS)) - 1);
var ENCODING_LIMIT_2_BYTES = ((1 << (XML_TT_VAL_BITS + XML_REG_VAL_BITS)) - 1);
var ENCODING_LIMIT_3_BYTES = ((1 << (XML_TT_VAL_BITS + 2 * XML_REG_VAL_BITS)) - 1);

BinaryXMLEncoder.prototype.numEncodingBytes = function(
    //long
    x)
{
  if (x <= ENCODING_LIMIT_1_BYTE) return (1);
  if (x <= ENCODING_LIMIT_2_BYTES) return (2);
  if (x <= ENCODING_LIMIT_3_BYTES) return (3);

  var numbytes = 1;

  // Last byte gives you XML_TT_VAL_BITS
  // Remainder each give you XML_REG_VAL_BITS
  x = x >>> XML_TT_VAL_BITS;
  while (x != 0) {
        numbytes++;
    x = x >>> XML_REG_VAL_BITS;
  }
  return (numbytes);
};

/**
 * Write an element start header using DTAG with the tag to the output buffer, then the dateTime
   * as a big endian BLOB converted to 4096 ticks per second, then an element close.
 * @param {number} tag The DTAG tag.
 * @param {NDNTime} dateTime
 */
BinaryXMLEncoder.prototype.writeDateTimeDTagElement = function(tag, dateTime)
{
  //parse to hex
  var binarydate =  Math.round((dateTime.msec/1000) * 4096).toString(16)  ;
  if (binarydate.length % 2 == 1)
    binarydate = '0' + binarydate;

  this.writeDTagElement(tag, DataUtils.toNumbers(binarydate));
};

/**
 * @deprecated Use writeDateTimeDTagElement.  Binary XML string tags and attributes are not used by any NDN encodings and
 * support is not maintained in the code base.
 */
BinaryXMLEncoder.prototype.writeDateTime = function(
    //String
    tag,
    //NDNTime
    dateTime)
{
  //parse to hex
  var binarydate =  Math.round((dateTime.msec/1000) * 4096).toString(16)  ;
  if (binarydate.length % 2 == 1)
    binarydate = '0' + binarydate;

  this.writeElement(tag, DataUtils.toNumbers(binarydate));
};

// This does not update this.offset.
BinaryXMLEncoder.prototype.writeString = function(input)
{
  if (typeof input === 'string') {
    if (LOG > 4) console.log('GOING TO WRITE A STRING');
    if (LOG > 4) console.log(input);

    this.ostream.ensureLength(this.offset + input.length);
    for (var i = 0; i < input.length; i++) {
      if (LOG > 4) console.log('input.charCodeAt(i)=' + input.charCodeAt(i));
      this.ostream.array[this.offset + i] = (input.charCodeAt(i));
    }
  }
  else
  {
    if (LOG > 4) console.log('GOING TO WRITE A STRING IN BINARY FORM');
    if (LOG > 4) console.log(input);

    this.writeBlobArray(input);
  }
};

BinaryXMLEncoder.prototype.writeBlobArray = function(
    //Buffer
    blob)
{
  if (LOG > 4) console.log('GOING TO WRITE A BLOB');

  this.ostream.copy(blob, this.offset);
};

BinaryXMLEncoder.prototype.getReducedOstream = function()
{
  return this.ostream.slice(0, this.offset);
};
