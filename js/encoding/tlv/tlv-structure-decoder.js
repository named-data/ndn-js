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
var TlvDecoder = require('./tlv-decoder.js').TlvDecoder;

/**
 * Create and initialize a TlvStructureDecoder.
 * @constructor
 */
var TlvStructureDecoder = function TlvStructureDecoder()
{
  this.gotElementEnd = false;
  this.offset = 0;
  this.state = TlvStructureDecoder.READ_TYPE;
  this.headerLength = 0;
  this.useHeaderBuffer = false;
  // 8 bytes is enough to hold the extended bytes in the length encoding
  // where it is an 8-byte number.
  this.headerBuffer = new Buffer(8);
  this.nBytesToRead = 0;
};

exports.TlvStructureDecoder = TlvStructureDecoder;

TlvStructureDecoder.READ_TYPE =         0;
TlvStructureDecoder.READ_TYPE_BYTES =   1;
TlvStructureDecoder.READ_LENGTH =       2;
TlvStructureDecoder.READ_LENGTH_BYTES = 3;
TlvStructureDecoder.READ_VALUE_BYTES =  4;

/**
 * Continue scanning input starting from this.offset to find the element end.
 * If the end of the element which started at offset 0 is found, this returns
 * true and getOffset() is the length of the element.  Otherwise, this returns
 * false which means you should read more into input and call again.
 * @param {Buffer} input The input buffer. You have to pass in input each time
 * because the buffer could be reallocated.
 * @returns {boolean} true if found the element end, false if not.
 */
TlvStructureDecoder.prototype.findElementEnd = function(input)
{
  if (this.gotElementEnd)
    // Someone is calling when we already got the end.
    return true;

  var decoder = new TlvDecoder(input);

  while (true) {
    if (this.offset >= input.length)
      // All the cases assume we have some input. Return and wait for more.
      return false;

    if (this.state == TlvStructureDecoder.READ_TYPE) {
      var firstOctet = input[this.offset];
      this.offset += 1;
      if (firstOctet < 253)
        // The value is simple, so we can skip straight to reading the length.
        this.state = TlvStructureDecoder.READ_LENGTH;
      else {
        // Set up to skip the type bytes.
        if (firstOctet == 253)
          this.nBytesToRead = 2;
        else if (firstOctet == 254)
          this.nBytesToRead = 4;
        else
          // value == 255.
          this.nBytesToRead = 8;

        this.state = TlvStructureDecoder.READ_TYPE_BYTES;
      }
    }
    else if (this.state == TlvStructureDecoder.READ_TYPE_BYTES) {
      var nRemainingBytes = input.length - this.offset;
      if (nRemainingBytes < this.nBytesToRead) {
        // Need more.
        this.offset += nRemainingBytes;
        this.nBytesToRead -= nRemainingBytes;
        return false;
      }

      // Got the type bytes. Move on to read the length.
      this.offset += this.nBytesToRead;
      this.state = TlvStructureDecoder.READ_LENGTH;
    }
    else if (this.state == TlvStructureDecoder.READ_LENGTH) {
      var firstOctet = input[this.offset];
      this.offset += 1;
      if (firstOctet < 253) {
        // The value is simple, so we can skip straight to reading
        //  the value bytes.
        this.nBytesToRead = firstOctet;
        if (this.nBytesToRead == 0) {
          // No value bytes to read. We're finished.
          this.gotElementEnd = true;
          return true;
        }

        this.state = TlvStructureDecoder.READ_VALUE_BYTES;
      }
      else {
        // We need to read the bytes in the extended encoding of
        //  the length.
        if (firstOctet == 253)
          this.nBytesToRead = 2;
        else if (firstOctet == 254)
          this.nBytesToRead = 4;
        else
          // value == 255.
          this.nBytesToRead = 8;

        // We need to use firstOctet in the next state.
        this.firstOctet = firstOctet;
        this.state = TlvStructureDecoder.READ_LENGTH_BYTES;
      }
    }
    else if (this.state == TlvStructureDecoder.READ_LENGTH_BYTES) {
      var nRemainingBytes = input.length - this.offset;
      if (!this.useHeaderBuffer && nRemainingBytes >= this.nBytesToRead) {
        // We don't have to use the headerBuffer. Set nBytesToRead.
        decoder.seek(this.offset);

        this.nBytesToRead = decoder.readExtendedVarNumber(this.firstOctet);
        // Update this.offset to the decoder's offset after reading.
        this.offset = decoder.getOffset();
      }
      else {
        this.useHeaderBuffer = true;

        var nNeededBytes = this.nBytesToRead - this.headerLength;
        if (nNeededBytes > nRemainingBytes) {
          // We can't get all of the header bytes from this input.
          // Save in headerBuffer.
          if (this.headerLength + nRemainingBytes > this.headerBuffer.length)
            // We don't expect this to happen.
            throw new Error
              ("Cannot store more header bytes than the size of headerBuffer");
          input.slice(this.offset, this.offset + nRemainingBytes).copy
            (this.headerBuffer, this.headerLength);
          this.offset += nRemainingBytes;
          this.headerLength += nRemainingBytes;

          return false;
        }

        // Copy the remaining bytes into headerBuffer, read the
        //   length and set nBytesToRead.
        if (this.headerLength + nNeededBytes > this.headerBuffer.length)
          // We don't expect this to happen.
          throw new Error
            ("Cannot store more header bytes than the size of headerBuffer");
        input.slice(this.offset, this.offset + nNeededBytes).copy
          (this.headerBuffer, this.headerLength);
        this.offset += nNeededBytes;

        // Use a local decoder just for the headerBuffer.
        var bufferDecoder = new TlvDecoder(this.headerBuffer);
        // Replace nBytesToRead with the length of the value.
        this.nBytesToRead = bufferDecoder.readExtendedVarNumber(this.firstOctet);
      }

      if (this.nBytesToRead == 0) {
        // No value bytes to read. We're finished.
        this.gotElementEnd = true;
        return true;
      }

      // Get ready to read the value bytes.
      this.state = TlvStructureDecoder.READ_VALUE_BYTES;
    }
    else if (this.state == TlvStructureDecoder.READ_VALUE_BYTES) {
      nRemainingBytes = input.length - this.offset;
      if (nRemainingBytes < this.nBytesToRead) {
        // Need more.
        this.offset += nRemainingBytes;
        this.nBytesToRead -= nRemainingBytes;
        return false;
      }

      // Got the bytes. We're finished.
      this.offset += this.nBytesToRead;
      this.gotElementEnd = true;
      return true;
    }
    else
      // We don't expect this to happen.
      throw new Error("findElementEnd: unrecognized state");
  }
};

/**
 * Get the current offset into the input buffer.
 * @returns {number} The offset.
 */
TlvStructureDecoder.prototype.getOffset = function()
{
  return this.offset;
};

/**
 * Set the offset into the input, used for the next read.
 * @param {number} offset The new offset.
 */
TlvStructureDecoder.prototype.seek = function(offset)
{
  this.offset = offset;
};
