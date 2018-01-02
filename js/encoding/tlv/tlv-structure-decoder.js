/**
 * Copyright (C) 2014-2018 Regents of the University of California.
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
 * A TlvStructureDecoder finds the end of an NDN-TLV element, even if the
 * element is supplied in parts.
 * Create and initialize a TlvStructureDecoder.
 * @constructor
 */
var TlvStructureDecoder = function TlvStructureDecoder()
{
  this.gotElementEnd_ = false;
  this.offset_ = 0;
  this.state_ = TlvStructureDecoder.READ_TYPE;
  this.headerLength_ = 0;
  this.useHeaderBuffer_ = false;
  // 8 bytes is enough to hold the extended bytes in the length encoding
  // where it is an 8-byte number.
  this.headerBuffer_ = new Buffer(8);
  this.nBytesToRead_ = 0;
};

exports.TlvStructureDecoder = TlvStructureDecoder;

TlvStructureDecoder.READ_TYPE =         0;
TlvStructureDecoder.READ_TYPE_BYTES =   1;
TlvStructureDecoder.READ_LENGTH =       2;
TlvStructureDecoder.READ_LENGTH_BYTES = 3;
TlvStructureDecoder.READ_VALUE_BYTES =  4;

/**
 * Continue scanning input starting from this.offset_ to find the element end.
 * If the end of the element which started at offset 0 is found, this returns
 * true and getOffset() is the length of the element.  Otherwise, this returns
 * false which means you should read more into input and call again.
 * @param {Buffer} input The input buffer. You have to pass in input each time
 * because the buffer could be reallocated.
 * @return {boolean} true if found the element end, false if not.
 */
TlvStructureDecoder.prototype.findElementEnd = function(input)
{
  if (this.gotElementEnd_)
    // Someone is calling when we already got the end.
    return true;

  var decoder = new TlvDecoder(input);

  while (true) {
    if (this.offset_ >= input.length)
      // All the cases assume we have some input. Return and wait for more.
      return false;

    if (this.state_ == TlvStructureDecoder.READ_TYPE) {
      var firstOctet = input[this.offset_];
      this.offset_ += 1;
      if (firstOctet < 253)
        // The value is simple, so we can skip straight to reading the length.
        this.state_ = TlvStructureDecoder.READ_LENGTH;
      else {
        // Set up to skip the type bytes.
        if (firstOctet == 253)
          this.nBytesToRead_ = 2;
        else if (firstOctet == 254)
          this.nBytesToRead_ = 4;
        else
          // value == 255.
          this.nBytesToRead_ = 8;

        this.state_ = TlvStructureDecoder.READ_TYPE_BYTES;
      }
    }
    else if (this.state_ == TlvStructureDecoder.READ_TYPE_BYTES) {
      var nRemainingBytes = input.length - this.offset_;
      if (nRemainingBytes < this.nBytesToRead_) {
        // Need more.
        this.offset_ += nRemainingBytes;
        this.nBytesToRead_ -= nRemainingBytes;
        return false;
      }

      // Got the type bytes. Move on to read the length.
      this.offset_ += this.nBytesToRead_;
      this.state_ = TlvStructureDecoder.READ_LENGTH;
    }
    else if (this.state_ == TlvStructureDecoder.READ_LENGTH) {
      var firstOctet = input[this.offset_];
      this.offset_ += 1;
      if (firstOctet < 253) {
        // The value is simple, so we can skip straight to reading
        //  the value bytes.
        this.nBytesToRead_ = firstOctet;
        if (this.nBytesToRead_ == 0) {
          // No value bytes to read. We're finished.
          this.gotElementEnd_ = true;
          return true;
        }

        this.state_ = TlvStructureDecoder.READ_VALUE_BYTES;
      }
      else {
        // We need to read the bytes in the extended encoding of
        //  the length.
        if (firstOctet == 253)
          this.nBytesToRead_ = 2;
        else if (firstOctet == 254)
          this.nBytesToRead_ = 4;
        else
          // value == 255.
          this.nBytesToRead_ = 8;

        // We need to use firstOctet in the next state.
        this.firstOctet_ = firstOctet;
        this.state_ = TlvStructureDecoder.READ_LENGTH_BYTES;
      }
    }
    else if (this.state_ == TlvStructureDecoder.READ_LENGTH_BYTES) {
      var nRemainingBytes = input.length - this.offset_;
      if (!this.useHeaderBuffer_ && nRemainingBytes >= this.nBytesToRead_) {
        // We don't have to use the headerBuffer. Set nBytesToRead.
        decoder.seek(this.offset_);

        this.nBytesToRead_ = decoder.readExtendedVarNumber(this.firstOctet_);
        // Update this.offset_ to the decoder's offset after reading.
        this.offset_ = decoder.getOffset();
      }
      else {
        this.useHeaderBuffer_ = true;

        var nNeededBytes = this.nBytesToRead_ - this.headerLength_;
        if (nNeededBytes > nRemainingBytes) {
          // We can't get all of the header bytes from this input.
          // Save in headerBuffer.
          if (this.headerLength_ + nRemainingBytes > this.headerBuffer_.length)
            // We don't expect this to happen.
            throw new Error
              ("Cannot store more header bytes than the size of headerBuffer");
          input.slice(this.offset_, this.offset_ + nRemainingBytes).copy
            (this.headerBuffer_, this.headerLength_);
          this.offset_ += nRemainingBytes;
          this.headerLength_ += nRemainingBytes;

          return false;
        }

        // Copy the remaining bytes into headerBuffer, read the
        //   length and set nBytesToRead.
        if (this.headerLength_ + nNeededBytes > this.headerBuffer_.length)
          // We don't expect this to happen.
          throw new Error
            ("Cannot store more header bytes than the size of headerBuffer");
        input.slice(this.offset_, this.offset_ + nNeededBytes).copy
          (this.headerBuffer_, this.headerLength_);
        this.offset_ += nNeededBytes;

        // Use a local decoder just for the headerBuffer.
        var bufferDecoder = new TlvDecoder(this.headerBuffer_);
        // Replace nBytesToRead with the length of the value.
        this.nBytesToRead_ = bufferDecoder.readExtendedVarNumber(this.firstOctet_);
      }

      if (this.nBytesToRead_ == 0) {
        // No value bytes to read. We're finished.
        this.gotElementEnd_ = true;
        return true;
      }

      // Get ready to read the value bytes.
      this.state_ = TlvStructureDecoder.READ_VALUE_BYTES;
    }
    else if (this.state_ == TlvStructureDecoder.READ_VALUE_BYTES) {
      var nRemainingBytes = input.length - this.offset_;
      if (nRemainingBytes < this.nBytesToRead_) {
        // Need more.
        this.offset_ += nRemainingBytes;
        this.nBytesToRead_ -= nRemainingBytes;
        return false;
      }

      // Got the bytes. We're finished.
      this.offset_ += this.nBytesToRead_;
      this.gotElementEnd_ = true;
      return true;
    }
    else
      // We don't expect this to happen.
      throw new Error("findElementEnd: unrecognized state");
  }
};

/**
 * Get the current offset into the input buffer.
 * @return {number} The offset.
 */
TlvStructureDecoder.prototype.getOffset = function()
{
  return this.offset_;
};

/**
 * Set the offset into the input, used for the next read.
 * @param {number} offset The new offset.
 */
TlvStructureDecoder.prototype.seek = function(offset)
{
  this.offset_ = offset;
};
