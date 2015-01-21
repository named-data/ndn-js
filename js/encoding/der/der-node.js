/**
 * Copyright (C) 2014-2015 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From PyNDN der_node.py by Adeola Bannis <thecodemaiden@gmail.com>.
 * @author: Originally from code in ndn-cxx by Yingdi Yu <yingdi@cs.ucla.edu>
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

var DynamicBuffer = require('../../util/dynamic-buffer.js').DynamicBuffer;
var Blob = require('../../util/blob.js').Blob;
var DerDecodingException = require('./der-decoding-exception.js').DerDecodingException;
var DerEncodingException = require('./der-encoding-exception.js').DerEncodingException;
var DerNodeType = require('./der-node-type.js').DerNodeType;

/**
 * DerNode implements the DER node types used in encoding/decoding DER-formatted
 * data.
 *
 * Create a generic DER node with the given nodeType. This is a private
 * constructor used by one of the public DerNode subclasses defined below.
 * @param {number} nodeType One of the defined DER DerNodeType constants.
 */
var DerNode = function DerNode(nodeType)
{
  this.nodeType = nodeType;
  this.parent = null;
  this.header = new Buffer(0);
  this.payload = new DynamicBuffer(0);
  this.payloadPosition = 0;
};

exports.DerNode = DerNode;

/**
 * Return the number of bytes in DER
 * @returns {number}
 */
DerNode.prototype.getSize = function()
{
  return this.header.length + this.payloadPosition;
};

/**
 * Encode the given size and update the header.
 * @param {number} size
 */
DerNode.prototype.encodeHeader = function(size)
{
  var buffer = new DynamicBuffer(10);
  var bufferPosition = 0;
  buffer.array[bufferPosition++] = this.nodeType;
  if (size < 0)
    // We don't expect this to happen since this is an internal method and
    // always called with the non-negative size() of some buffer.
    throw new Error("encodeHeader: DER object has negative length");
  else if (size <= 127)
    buffer.array[bufferPosition++] = size & 0xff;
  else {
    var tempBuf = new DynamicBuffer(10);
    // We encode backwards from the back.

    var val = size;
    var n = 0;
    while (val != 0) {
      ++n;
      tempBuf.ensureLengthFromBack(n);
      tempBuf.array[tempBuf.array.length - n] = val & 0xff;
      val >>= 8;
    }
    var nTempBufBytes = n + 1;
    tempBuf.ensureLengthFromBack(nTempBufBytes);
    tempBuf.array[tempBuf.array.length - nTempBufBytes] = ((1<<7) | n) & 0xff;

    buffer.copy(tempBuf.slice(tempBuf.array.length - nTempBufBytes), bufferPosition);
    bufferPosition += nTempBufBytes;
  }

  this.header = buffer.slice(0, bufferPosition);
};

/**
 * Extract the header from an input buffer and return the size.
 * @param {Buffer} inputBuf The input buffer to read from.
 * @param {number} startIdx The offset into the buffer.
 * @returns {number} The parsed size in the header.
 */
DerNode.prototype.decodeHeader = function(inputBuf, startIdx)
{
  var idx = startIdx;

  var nodeType = inputBuf[idx] & 0xff;
  idx += 1;

  this.nodeType = nodeType;

  var sizeLen = inputBuf[idx] & 0xff;
  idx += 1;

  var header = new DynamicBuffer(10);
  var headerPosition = 0;
  header.array[headerPosition++] = nodeType;
  header.array[headerPosition++] = sizeLen;

  var size = sizeLen;
  var isLongFormat = (sizeLen & (1 << 7)) != 0;
  if (isLongFormat) {
    var lenCount = sizeLen & ((1<<7) - 1);
    size = 0;
    while (lenCount > 0) {
      var b = inputBuf[idx];
      idx += 1;
      header.ensureLength(headerPosition + 1);
      header.array[headerPosition++] = b;
      size = 256 * size + (b & 0xff);
      lenCount -= 1;
    }
  }

  this.header = header.slice(0, headerPosition);
  return size;
};

/**
 * Get the raw data encoding for this node.
 * @returns {Blob} The raw data encoding.
 */
DerNode.prototype.encode = function()
{
  var buffer = new Buffer(this.getSize());

  this.header.copy(buffer);
  this.payload.slice(0, this.payloadPosition).copy(buffer, this.header.length);

  return new Blob(buffer, false);
};

/**
 * Decode and store the data from an input buffer.
 * @param {Buffer} inputBuf The input buffer to read from. This reads from
 * startIdx (regardless of the buffer's position) and does not change the
 * position.
 * @param {number} startIdx The offset into the buffer.
 */
DerNode.prototype.decode = function(inputBuf, startIdx)
{
  var idx = startIdx;
  var payloadSize = this.decodeHeader(inputBuf, idx);
  var skipBytes = this.header.length;
  if (payloadSize > 0) {
    idx += skipBytes;
    this.payloadAppend(inputBuf.slice(idx, idx + payloadSize));
  }
};

/**
 * Copy buffer to this.payload at this.payloadPosition and update
 * this.payloadPosition.
 * @param {Buffer} buffer The buffer to copy.
 */
DerNode.prototype.payloadAppend = function(buffer)
{
  this.payloadPosition = this.payload.copy(buffer, this.payloadPosition);
}

/**
 * Parse the data from the input buffer recursively and return the root as an
 * object of a subclass of DerNode.
 * @param {type} inputBuf The input buffer to read from.
 * @param {type} startIdx (optional) The offset into the buffer. If omitted, use 0.
 * @returns {DerNode} An object of a subclass of DerNode.
 */
DerNode.parse = function(inputBuf, startIdx)
{
  if (startIdx == undefined)
    startIdx = 0;
  
  var nodeType = inputBuf[startIdx] & 0xff;
  // Don't increment idx. We're just peeking.

  var newNode;
  if (nodeType === DerNodeType.Boolean)
    newNode = new DerNode.DerBoolean();
  else if (nodeType === DerNodeType.Integer)
    newNode = new DerNode.DerInteger();
  else if (nodeType === DerNodeType.BitString)
    newNode = new DerNode.DerBitString();
  else if (nodeType === DerNodeType.OctetString)
    newNode = new DerNode.DerOctetString();
  else if (nodeType === DerNodeType.Null)
    newNode = new DerNode.DerNull();
  else if (nodeType === DerNodeType.ObjectIdentifier)
    newNode = new DerNode.DerOid();
  else if (nodeType === DerNodeType.Sequence)
    newNode = new DerNode.DerSequence();
  else if (nodeType === DerNodeType.PrintableString)
    newNode = new DerNode.DerPrintableString();
  else if (nodeType === DerNodeType.GeneralizedTime)
    newNode = new DerNode.DerGeneralizedTime();
  else
    throw new DerDecodingException(new Error("Unimplemented DER type " + nodeType));

  newNode.decode(inputBuf, startIdx);
  return newNode;
};

/**
 * Convert the encoded data to a standard representation. Overridden by some
 * subclasses (e.g. DerBoolean).
 * @returns {Blob} The encoded data as a Blob.
 */
DerNode.prototype.toVal = function()
{
  return this.encode();
};

/**
 * If this object is a DerNode.DerSequence, get the children of this node.
 * Otherwise, throw an exception. (DerSequence overrides to implement this
 * method.)
 * @returns {Array<DerNode>} The children as an array of DerNode.
 * @throws DerDecodingException if this object is not a DerSequence.
 */
DerNode.prototype.getChildren = function()
{
  throw new DerDecodingException(new Error
    ("getChildren: This DerNode is not DerSequence"));
};

/**
 * Check that index is in bounds for the children list, return children[index].
 * @param {Array<DerNode>} children The list of DerNode, usually returned by
 * another call to getChildren.
 * @param {number} index The index of the children.
 * @return {DerNode.DerSequence} children[index].
 * @throws DerDecodingException if index is out of bounds or if children[index]
 * is not a DerSequence.
 */
DerNode.getSequence = function(children, index)
{
  if (index < 0 || index >= children.length)
    throw new DerDecodingException(new Error
      ("getSequence: Child index is out of bounds"));

  if (!(children[index] instanceof DerNode.DerSequence))
    throw new DerDecodingException(new Error
      ("getSequence: Child DerNode is not a DerSequence"));

  return children[index];
};

/**
 * A DerStructure extends DerNode to hold other DerNodes.
 * Create a DerStructure with the given nodeType. This is a private
 * constructor. To create an object, use DerSequence.
 * @param {number} nodeType One of the defined DER DerNodeType constants.
 */
DerNode.DerStructure = function DerStructure(nodeType)
{
  // Call the base constructor.
  DerNode.call(this, nodeType);

  this.childChanged = false;
  this.nodeList = []; // Of DerNode.
  this.size = 0;
};
DerNode.DerStructure.prototype = new DerNode();
DerNode.DerStructure.prototype.name = "DerStructure";

/**
 * Get the total length of the encoding, including children.
 * @returns {number} The total (header + payload) length.
 */
DerNode.DerStructure.prototype.getSize = function()
{
  if (this.childChanged) {
    this.updateSize();
    this.childChanged = false;
  }

  this.encodeHeader(this.size);
  return this.size + this.header.length;
};

/**
 * Get the children of this node.
 * @returns {Array<DerNode>} The children as an array of DerNode.
 */
DerNode.DerStructure.prototype.getChildren = function()
{
  return this.nodeList;
};

DerNode.DerStructure.prototype.updateSize = function()
{
  var newSize = 0;

  for (var i = 0; i < this.nodeList.length; ++i) {
    var n = this.nodeList[i];
    newSize += n.getSize();
  }

  this.size = newSize;
  this.childChanged = false;
};

/**
 * Add a child to this node.
 * @param {DerNode} node The child node to add.
 * @param {boolean} (optional) notifyParent Set to true to cause any containing
 * nodes to update their size.  If omitted, use false.
 */
DerNode.DerStructure.prototype.addChild = function(node, notifyParent)
{
  node.parent = this;
  this.nodeList.push(node);

  if (notifyParent) {
    if (this.parent != null)
      this.parent.setChildChanged();
  }

  this.childChanged = true;
};

/**
 * Mark the child list as dirty, so that we update size when necessary.
 */
DerNode.DerStructure.prototype.setChildChanged = function()
{
  if (this.parent != null)
    this.parent.setChildChanged();
  this.childChanged = true;
};

/**
 * Override the base encode to return raw data encoding for this node and its 
 * children.
 * @returns {Blob} The raw data encoding.
 */
DerNode.DerStructure.prototype.encode = function()
{
  var buffer = new DynamicBuffer(10);
  var bufferPosition = 0;
  this.updateSize();
  this.encodeHeader(this.size);
  bufferPosition = buffer.copy(this.header, bufferPosition);

  for (var i = 0; i < this.nodeList.length; ++i) {
    var n = this.nodeList[i];
    var encodedChild = n.encode();
    bufferPosition = buffer.copy(encodedChild.buf(), bufferPosition);
  }

  return new Blob(buffer.slice(0, bufferPosition), false);
};

/**
 * Override the base decode to decode and store the data from an input
 * buffer. Recursively populates child nodes.
 * @param {Buffer} inputBuf The input buffer to read from.
 * @param {number} startIdx The offset into the buffer.
 */
DerNode.DerStructure.prototype.decode = function(inputBuf, startIdx)
{
  var idx = startIdx;
  this.size = this.decodeHeader(inputBuf, idx);
  idx += this.header.length;

  var accSize = 0;
  while (accSize < this.size) {
    var node = DerNode.parse(inputBuf, idx);
    idx += node.getSize();
    accSize += node.getSize();
    this.addChild(node, false);
  }
};

////////
// Now for all the node types...
////////

/**
 * A DerByteString extends DerNode to handle byte strings.
 * Create a DerByteString with the given inputData and nodeType. This is a
 * private constructor used by one of the public subclasses such as
 * DerOctetString or DerPrintableString.
 * @param {Buffer} inputData An input buffer containing the string to encode.
 * @param {number} nodeType One of the defined DER DerNodeType constants.
 */
DerNode.DerByteString = function DerByteString(inputData, nodeType)
{
  // Call the base constructor.
  DerNode.call(this, nodeType);

  if (inputData != null) {
    this.payloadAppend(inputData);
    this.encodeHeader(inputData.length);
  }
};
DerNode.DerByteString.prototype = new DerNode();
DerNode.DerByteString.prototype.name = "DerByteString";

/**
 * Override to return just the byte string.
 * @returns {Blob} The byte string as a copy of the payload buffer.
 */
DerNode.DerByteString.prototype.toVal = function()
{
  // Make a copy since this.payload can change.
  return new Blob(this.payload.slice(0, this.payloadPosition), true);
};

/**
 * DerBoolean extends DerNode to encode a boolean value.
 * Create a new DerBoolean for the value.
 * @param {boolean} value The value to encode.
 */
DerNode.DerBoolean = function DerBoolean(value)
{
  // Call the base constructor.
  DerNode.call(this, DerNodeType.Boolean);

  if (value != undefined) {
    var val = value ? 0xff : 0x00;
    this.payload.ensureLength(this.payloadPosition + 1);
    this.payload.array[this.payloadPosition++] = val;
    this.encodeHeader(1);
  }
};
DerNode.DerBoolean.prototype = new DerNode();
DerNode.DerBoolean.prototype.name = "DerBoolean";

DerNode.DerBoolean.prototype.toVal = function()
{
  var val = this.payload.array[0];
  return val != 0x00;
};

/**
 * DerInteger extends DerNode to encode an integer value.
 * Create a new DerInteger for the value.
 * @param {number} integer The value to encode.
 */
DerNode.DerInteger = function DerInteger(integer)
{
  // Call the base constructor.
  DerNode.call(this, DerNodeType.Integer);

  if (integer != undefined) {
    // JavaScript doesn't distinguish int from float, so round.
    integer = Math.round(integer);

    // Convert the integer to bytes the easy/slow way.
    var temp = new DynamicBuffer(10);
    // We encode backwards from the back.
    var length = 0;
    while (true) {
      ++length;
      temp.ensureLengthFromBack(length);
      temp.array[temp.array.length - length] = integer & 0xff;
      integer >>= 8;

      if (integer <= 0)
        // We check for 0 at the end so we encode one byte if it is 0.
        break;
    }

    this.payloadAppend(temp.slice(temp.array.length - length));
    this.encodeHeader(this.payloadPosition);
  }
};
DerNode.DerInteger.prototype = new DerNode();
DerNode.DerInteger.prototype.name = "DerInteger";

DerNode.DerInteger.prototype.toVal = function()
{
  var result = 0;
  for (var i = 0; i < this.payloadPosition; ++i) {
    result <<= 8;
    result += this.payload.array[i];
  }

  return result;
};

/**
 * A DerBitString extends DerNode to handle a bit string.
 * Create a DerBitString with the given padding and inputBuf.
 * @param {Buffer} inputBuf An input buffer containing the bit octets to encode.
 * @param {number} paddingLen The number of bits of padding at the end of the bit
 * string.  Should be less than 8.
 */
DerNode.DerBitString = function DerBitString(inputBuf, paddingLen)
{
  // Call the base constructor.
  DerNode.call(this, DerNodeType.BitString);

  if (inputBuf != undefined) {
    this.payload.ensureLength(this.payloadPosition + 1);
    this.payload.array[this.payloadPosition++] = paddingLen & 0xff;
    this.payloadAppend(inputBuf);
    this.encodeHeader(this.payloadPosition);
  }
};
DerNode.DerBitString.prototype = new DerNode();
DerNode.DerBitString.prototype.name = "DerBitString";

/**
 * DerOctetString extends DerByteString to encode a string of bytes.
 * Create a new DerOctetString for the inputData.
 * @param {type} inputData An input buffer containing the string to encode.
 */
DerNode.DerOctetString = function DerOctetString(inputData)
{
  // Call the base constructor.
  DerNode.DerByteString.call(this, inputData, DerNodeType.OctetString);
};
DerNode.DerOctetString.prototype = new DerNode.DerByteString();
DerNode.DerOctetString.prototype.name = "DerOctetString";

/**
 * A DerNull extends DerNode to encode a null value.
 * Create a DerNull.
 */
DerNode.DerNull = function DerNull()
{
  // Call the base constructor.
  DerNode.call(this, DerNodeType.Null);
  this.encodeHeader(0);
};
DerNode.DerNull.prototype = new DerNode();
DerNode.DerNull.prototype.name = "DerNull";

/**
 * A DerOid extends DerNode to represent an object identifier.
 * Create a DerOid with the given object identifier. The object identifier
 * string must begin with 0,1, or 2 and must contain at least 2 digits.
 * @param {string|OID} oid The OID string or OID object to encode.
 */
DerNode.DerOid = function DerOid(oid)
{
  // Call the base constructor.
  DerNode.call(this, DerNodeType.ObjectIdentifier);

  if (oid != undefined) {
    if (typeof oid === 'string') {
      var splitString = oid.split(".");
      var parts = [];
      for (var i = 0; i < splitString.length; ++i)
        parts.push(parseInt(splitString[i]));

      this.prepareEncoding(parts);
    }
    else
      // Assume oid is of type OID.
      this.prepareEncoding(oid.getIntegerList());
  }
};
DerNode.DerOid.prototype = new DerNode();
DerNode.DerOid.prototype.name = "DerOid";

/**
 * Encode a sequence of integers into an OID object and set the payload.
 * @param {Array<number>} value The array of integers.
 */
DerNode.DerOid.prototype.prepareEncoding = function(value)
{
  var firstNumber;
  if (value.length == 0)
    throw new DerEncodingException(new Error("No integer in OID"));
  else {
    if (value[0] >= 0 && value[0] <= 2)
      firstNumber = value[0] * 40;
    else
      throw new DerEncodingException(new Error("First integer in OID is out of range"));
  }

  if (value.length >= 2) {
    if (value[1] >= 0 && value[1] <= 39)
      firstNumber += value[1];
    else
      throw new DerEncodingException(new Error("Second integer in OID is out of range"));
  }

  var encodedBuffer = new DynamicBuffer(10);
  var encodedBufferPosition = 0;
  encodedBufferPosition = encodedBuffer.copy
    (DerNode.DerOid.encode128(firstNumber), encodedBufferPosition);

  if (value.length > 2) {
    for (var i = 2; i < value.length; ++i)
      encodedBufferPosition = encodedBuffer.copy
        (DerNode.DerOid.encode128(value[i]), encodedBufferPosition);
  }

  this.encodeHeader(encodedBufferPosition);
  this.payloadAppend(encodedBuffer.slice(0, encodedBufferPosition));
};

/**
 * Compute the encoding for one part of an OID, where values greater than 128
 * must be encoded as multiple bytes.
 * @param {number} value A component of an OID.
 * @returns {Buffer} The encoded buffer.
 */
DerNode.DerOid.encode128 = function(value)
{
  var mask = (1 << 7) - 1;
  var outBytes = new DynamicBuffer(10);
  var outBytesLength = 0;
  // We encode backwards from the back.

  if (value < 128) {
    ++outBytesLength;
    outBytes.array[outBytes.array.length - outBytesLength] = value & mask;
  }
  else {
    ++outBytesLength;
    outBytes.array[outBytes.array.length - outBytesLength] = value & mask;
    value >>= 7;

    while (value != 0) {
      ++outBytesLength;
      outBytes.ensureLengthFromBack(outBytesLength);
      outBytes.array[outBytes.array.length - outBytesLength] =
        (value & mask) | (1 << 7);
      value >>= 7;
    }
  }

  return outBytes.slice(outBytes.array.length - outBytesLength);
};

/**
 * Convert an encoded component of the encoded OID to the original integer.
 * @param {number} offset The offset into this node's payload.
 * @param {Array<number>} skip Set skip[0] to the number of payload bytes to skip.
 * @returns {number} The original integer.
 */
DerNode.DerOid.prototype.decode128 = function(offset, skip)
{
  var flagMask = 0x80;
  var result = 0;
  var oldOffset = offset;

  while ((this.payload.array[offset] & flagMask) != 0) {
    result = 128 * result + (this.payload.array[offset] & 0xff) - 128;
    offset += 1;
  }

  result = result * 128 + (this.payload.array[offset] & 0xff);

  skip[0] = offset - oldOffset + 1;
  return result;
};

/**
 * Override to return the string representation of the OID.
 * @returns {string} The string representation of the OID.
 */
DerNode.DerOid.prototype.toVal = function()
{
  var offset = 0;
  var components = []; // of number.

  while (offset < this.payloadPosition) {
    var skip = [0];
    var nextVal = this.decode128(offset, skip);
    offset += skip[0];
    components.push(nextVal);
  }

  // For some odd reason, the first digits are represented in one byte.
  var firstByte = components[0];
  var firstDigit = Math.floor(firstByte / 40);
  var secondDigit = firstByte % 40;

  var result = firstDigit + "." + secondDigit;
  for (var i = 1; i < components.length; ++i)
    result += "." + components[i];

  return result;
};

/**
 * A DerSequence extends DerStructure to contains an ordered sequence of other
 * nodes.
 * Create a DerSequence.
 */
DerNode.DerSequence = function DerSequence()
{
  // Call the base constructor.
  DerNode.DerStructure.call(this, DerNodeType.Sequence);
};
DerNode.DerSequence.prototype = new DerNode.DerStructure();
DerNode.DerSequence.prototype.name = "DerSequence";

/**
 * A DerPrintableString extends DerByteString to handle a a printable string. No
 * escaping or other modification is done to the string.
 * Create a DerPrintableString with the given inputData.
 * @param {Buffer} inputData An input buffer containing the string to encode.
 */
DerNode.DerPrintableString = function DerPrintableString(inputData)
{
  // Call the base constructor.
  DerNode.DerByteString.call(this, inputData, DerNodeType.PrintableString);
};
DerNode.DerPrintableString.prototype = new DerNode.DerByteString();
DerNode.DerPrintableString.prototype.name = "DerPrintableString";

/**
 * A DerGeneralizedTime extends DerNode to represent a date and time, with
 * millisecond accuracy.
 * Create a DerGeneralizedTime with the given milliseconds since 1970.
 * @param {number} msSince1970 The timestamp as milliseconds since Jan 1, 1970.
 */
DerNode.DerGeneralizedTime = function DerGeneralizedTime(msSince1970)
{
  // Call the base constructor.
  DerNode.call(this, DerNodeType.GeneralizedTime);

  if (msSince1970 != undefined) {
    var derTime = DerNode.DerGeneralizedTime.toDerTimeString(msSince1970);
    // Use Blob to convert to a Buffer.
    this.payloadAppend(new Blob(derTime).buf());
    this.encodeHeader(this.payloadPosition);
  }
};
DerNode.DerGeneralizedTime.prototype = new DerNode();
DerNode.DerGeneralizedTime.prototype.name = "DerGeneralizedTime";

/**
 * Convert a UNIX timestamp to the internal string representation.
 * @param {type} msSince1970 Timestamp as milliseconds since Jan 1, 1970.
 * @returns {string} The string representation.
 */
DerNode.DerGeneralizedTime.toDerTimeString = function(msSince1970)
{
  var utcTime = new Date(Math.round(msSince1970));
  return utcTime.getUTCFullYear() +
         DerNode.DerGeneralizedTime.to2DigitString(utcTime.getUTCMonth() + 1) +
         DerNode.DerGeneralizedTime.to2DigitString(utcTime.getUTCDate()) +
         DerNode.DerGeneralizedTime.to2DigitString(utcTime.getUTCHours()) +
         DerNode.DerGeneralizedTime.to2DigitString(utcTime.getUTCMinutes()) +
         DerNode.DerGeneralizedTime.to2DigitString(utcTime.getUTCSeconds()) +
         "Z";
};

/**
 * A private method to zero pad an integer to 2 digits.
 * @param {number} x The number to pad.  Assume it is a non-negative integer.
 * @returns {string} The padded string.
 */
DerNode.DerGeneralizedTime.to2DigitString = function(x)
{
  var result = x.toString();
  return result.length === 1 ? "0" + result : result;
};

/**
 * Override to return the milliseconds since 1970.
 * @returns {number} The timestamp value as milliseconds since 1970.
 */
DerNode.DerGeneralizedTime.prototype.toVal = function()
{
  var timeStr = this.payload.slice(0, this.payloadPosition).toString();
  return Date.UTC
    (parseInt(timeStr.substr(0, 4)),
     parseInt(timeStr.substr(4, 2) - 1),
     parseInt(timeStr.substr(6, 2)),
     parseInt(timeStr.substr(8, 2)),
     parseInt(timeStr.substr(10, 2)),
     parseInt(timeStr.substr(12, 2)));
};
