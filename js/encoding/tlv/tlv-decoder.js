/**
 * Copyright (C) 2014-2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
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
var DecodingException = require('../decoding-exception.js').DecodingException;

/**
 * Create a new TlvDecoder for decoding the input in the NDN-TLV wire format.
 * @constructor
 * @param {Buffer} input The buffer with the bytes to decode.
 */
var TlvDecoder = function TlvDecoder(input)
{
  this.input = input;
  this.offset = 0;
};

exports.TlvDecoder = TlvDecoder;

/**
 * Decode VAR-NUMBER in NDN-TLV and return it. Update offset.
 * @returns {number} The decoded VAR-NUMBER.
 */
TlvDecoder.prototype.readVarNumber = function()
{
  // Assume array values are in the range 0 to 255.
  var firstOctet = this.input[this.offset];
  this.offset += 1;
  if (firstOctet < 253)
    return firstOctet;
  else
    return this.readExtendedVarNumber(firstOctet);
};

/**
 * A private function to do the work of readVarNumber, given the firstOctet
 * which is >= 253.
 * @param {number} firstOctet The first octet which is >= 253, used to decode
 * the remaining bytes.
 * @returns {number} The decoded VAR-NUMBER.
 */
TlvDecoder.prototype.readExtendedVarNumber = function(firstOctet)
{
  var result;
  // This is a private function so we know firstOctet >= 253.
  if (firstOctet == 253) {
    result = ((this.input[this.offset] << 8) +
           this.input[this.offset + 1]);
    this.offset += 2;
  }
  else if (firstOctet == 254) {
    // Use abs because << 24 can set the high bit of the 32-bit int making it negative.
    result = (Math.abs(this.input[this.offset] << 24) +
          (this.input[this.offset + 1] << 16) +
          (this.input[this.offset + 2] << 8) +
           this.input[this.offset + 3]);
    this.offset += 4;
  }
  else {
    // Get the high byte first because JavaScript << is restricted to 32 bits.
    // Use abs because << 24 can set the high bit of the 32-bit int making it negative.
    var highByte = Math.abs(this.input[this.offset] << 24) +
                           (this.input[this.offset + 1] << 16) +
                           (this.input[this.offset + 2] << 8) +
                            this.input[this.offset + 3];
    result = (highByte * 0x100000000 +
          (this.input[this.offset + 4] << 24) +
          (this.input[this.offset + 5] << 16) +
          (this.input[this.offset + 6] << 8) +
           this.input[this.offset + 7]);
    this.offset += 8;
  }

  return result;
};

/**
 * Decode the type and length from this's input starting at offset, expecting
 * the type to be expectedType and return the length. Update offset.  Also make
 * sure the decoded length does not exceed the number of bytes remaining in the
 * input.
 * @param {number} expectedType The expected type.
 * @returns {number} The length of the TLV.
 * @throws DecodingException if (did not get the expected TLV type or the TLV length
 * exceeds the buffer length.
 */
TlvDecoder.prototype.readTypeAndLength = function(expectedType)
{
  var type = this.readVarNumber();
  if (type != expectedType)
    throw new DecodingException(new Error("Did not get the expected TLV type"));

  var length = this.readVarNumber();
  if (this.offset + length > this.input.length)
    throw new DecodingException(new Error("TLV length exceeds the buffer length"));

  return length;
};

/**
 * Decode the type and length from the input starting at offset, expecting the
 * type to be expectedType.  Update offset.  Also make sure the decoded length
 * does not exceed the number of bytes remaining in the input. Return the offset
 * of the end of this parent TLV, which is used in decoding optional nested
 * TLVs. After reading all nested TLVs, call finishNestedTlvs.
 * @param {number} expectedType The expected type.
 * @returns {number} The offset of the end of the parent TLV.
 * @throws DecodingException if did not get the expected TLV type or the TLV
 * length exceeds the buffer length.
 */
TlvDecoder.prototype.readNestedTlvsStart = function(expectedType)
{
  return this.readTypeAndLength(expectedType) + this.offset;
};

/**
 * Call this after reading all nested TLVs to skip any remaining unrecognized
 * TLVs and to check if the offset after the final nested TLV matches the
 * endOffset returned by readNestedTlvsStart.
 * @param {number} endOffset The offset of the end of the parent TLV, returned
 * by readNestedTlvsStart.
 * @throws DecodingException if the TLV length does not equal the total length
 * of the nested TLVs.
 */
TlvDecoder.prototype.finishNestedTlvs = function(endOffset)
{
  // We expect offset to be endOffset, so check this first.
  if (this.offset == endOffset)
    return;

  // Skip remaining TLVs.
  while (this.offset < endOffset) {
    // Skip the type VAR-NUMBER.
    this.readVarNumber();
    // Read the length and update offset.
    var length = this.readVarNumber();
    this.offset += length;

    if (this.offset > this.input.length)
      throw new DecodingException(new Error("TLV length exceeds the buffer length"));
  }

  if (this.offset != endOffset)
    throw new DecodingException(new Error
      ("TLV length does not equal the total length of the nested TLVs"));
};

/**
 * Decode the type from this's input starting at offset, and if it is the
 * expectedType, then return true, else false.  However, if this's offset is
 * greater than or equal to endOffset, then return false and don't try to read
 * the type. Do not update offset.
 * @param {number} expectedType The expected type.
 * @param {number} endOffset The offset of the end of the parent TLV, returned
 * by readNestedTlvsStart.
 * @returns {boolean} true if the type of the next TLV is the expectedType,
 *  otherwise false.
 */
TlvDecoder.prototype.peekType = function(expectedType, endOffset)
{
  if (this.offset >= endOffset)
    // No more sub TLVs to look at.
    return false;
  else {
    var saveOffset = this.offset;
    var type = this.readVarNumber();
    // Restore offset.
    this.offset = saveOffset;

    return type == expectedType;
  }
};

/**
 * Decode a non-negative integer in NDN-TLV and return it. Update offset by
 * length.
 * @param {number} length The number of bytes in the encoded integer.
 * @returns {number} The integer.
 * @throws DecodingException if length is an invalid length for a TLV
 * non-negative integer.
 */
TlvDecoder.prototype.readNonNegativeInteger = function(length)
{
  var result;
  if (length == 1)
    result = this.input[this.offset];
  else if (length == 2)
    result = ((this.input[this.offset] << 8) +
           this.input[this.offset + 1]);
  else if (length == 4)
    // Use abs because << 24 can set the high bit of the 32-bit int making it negative.
    result = (Math.abs(this.input[this.offset] << 24) +
          (this.input[this.offset + 1] << 16) +
          (this.input[this.offset + 2] << 8) +
           this.input[this.offset + 3]);
  else if (length == 8) {
    // Use abs because << 24 can set the high bit of the 32-bit int making it negative.
    var highByte = Math.abs(this.input[this.offset] << 24) +
                       (this.input[this.offset + 1] << 16) +
                       (this.input[this.offset + 2] << 8) +
                        this.input[this.offset + 3];
    result = (highByte * 0x100000000 +
          Math.abs(this.input[this.offset + 4] << 24) +
          (this.input[this.offset + 5] << 16) +
          (this.input[this.offset + 6] << 8) +
           this.input[this.offset + 7]);
  }
  else
    throw new DecodingException(new Error("Invalid length for a TLV nonNegativeInteger"));

  this.offset += length;
  return result;
};

/**
 * Decode the type and length from this's input starting at offset, expecting
 * the type to be expectedType. Then decode a non-negative integer in NDN-TLV
 * and return it.  Update offset.
 * @param {number} expectedType The expected type.
 * @returns {number} The integer.
 * @throws DecodingException if did not get the expected TLV type or can't
 * decode the value.
 */
TlvDecoder.prototype.readNonNegativeIntegerTlv = function(expectedType)
{
  var length = this.readTypeAndLength(expectedType);
  return this.readNonNegativeInteger(length);
};

/**
 * Peek at the next TLV, and if it has the expectedType then call
 * readNonNegativeIntegerTlv and return the integer.  Otherwise, return null.
 * However, if this's offset is greater than or equal to endOffset, then return
 * null and don't try to read the type.
 * @param {number} expectedType The expected type.
 * @param {number} endOffset The offset of the end of the parent TLV, returned
 * by readNestedTlvsStart.
 * @returns {number} The integer or null if the next TLV doesn't have the
 * expected type.
 */
TlvDecoder.prototype.readOptionalNonNegativeIntegerTlv = function
  (expectedType, endOffset)
{
  if (this.peekType(expectedType, endOffset))
    return this.readNonNegativeIntegerTlv(expectedType);
  else
    return null;
};

/**
 * Decode the type and length from this's input starting at offset, expecting
 * the type to be expectedType. Then return an array of the bytes in the value.
 * Update offset.
 * @param {number} expectedType The expected type.
 * @returns {Buffer} The bytes in the value as a slice on the buffer.  This is
 * not a copy of the bytes in the input buffer.  If you need a copy, then you
 * must make a copy of the return value.
 * @throws DecodingException if did not get the expected TLV type.
 */
TlvDecoder.prototype.readBlobTlv = function(expectedType)
{
  var length = this.readTypeAndLength(expectedType);
  var result = this.input.slice(this.offset, this.offset + length);

  // readTypeAndLength already checked if length exceeds the input buffer.
  this.offset += length;
  return result;
};

/**
 * Peek at the next TLV, and if it has the expectedType then call readBlobTlv
 * and return the value.  Otherwise, return null. However, if this's offset is
 * greater than or equal to endOffset, then return null and don't try to read
 * the type.
 * @param {number} expectedType The expected type.
 * @param {number} endOffset The offset of the end of the parent TLV, returned
 * by readNestedTlvsStart.
 * @returns {Buffer} The bytes in the value as a slice on the buffer or null if
 * the next TLV doesn't have the expected type.  This is not a copy of the bytes
 * in the input buffer.  If you need a copy, then you must make a copy of the
 * return value.
 */
TlvDecoder.prototype.readOptionalBlobTlv = function(expectedType, endOffset)
{
  if (this.peekType(expectedType, endOffset))
    return this.readBlobTlv(expectedType);
  else
    return null;
};

/**
 * Peek at the next TLV, and if it has the expectedType then read a type and
 * value, ignoring the value, and return true. Otherwise, return false.
 * However, if this's offset is greater than or equal to endOffset, then return
 * false and don't try to read the type.
 * @param {number} expectedType The expected type.
 * @param {number} endOffset The offset of the end of the parent TLV, returned
 * by readNestedTlvsStart.
 * @returns {boolean} true, or else false if the next TLV doesn't have the
 * expected type.
 */
TlvDecoder.prototype.readBooleanTlv = function(expectedType, endOffset)
{
  if (this.peekType(expectedType, endOffset)) {
    var length = this.readTypeAndLength(expectedType);
    // We expect the length to be 0, but update offset anyway.
    this.offset += length;
    return true;
  }
  else
    return false;
};

/**
 * Get the offset into the input, used for the next read.
 * @returns {number} The offset.
 */
TlvDecoder.prototype.getOffset = function()
{
  return this.offset;
};

/**
 * Set the offset into the input, used for the next read.
 * @param {number} offset The new offset.
 */
TlvDecoder.prototype.seek = function(offset)
{
  this.offset = offset;
};

/**
 * Return an array of a slice of the input for the given offset range.
 * @param {number} beginOffset The offset in the input of the beginning of the
 * slice.
 * @param {number} endOffset The offset in the input of the end of the slice.
 * @returns {Buffer} The bytes in the value as a slice on the buffer.  This is
 * not a copy of the bytes in the input buffer.  If you need a copy, then you
 * must make a copy of the return value.
 */
TlvDecoder.prototype.getSlice = function(beginOffset, endOffset)
{
  return this.input.slice(beginOffset, endOffset);
};
