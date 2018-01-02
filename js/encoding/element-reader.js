/**
 * Copyright (C) 2013-2018 Regents of the University of California.
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
var DataUtils = require('./data-utils.js').DataUtils; /** @ignore */
var Tlv = require('./tlv/tlv.js').Tlv; /** @ignore */
var TlvStructureDecoder = require('./tlv/tlv-structure-decoder.js').TlvStructureDecoder; /** @ignore */
var DecodingException = require('./decoding-exception.js').DecodingException; /** @ignore */
var NdnCommon = require('../util/ndn-common.js').NdnCommon; /** @ignore */
var LOG = require('../log.js').Log.LOG;

/**
 * A ElementReader lets you call onReceivedData multiple times which uses a
 * TlvStructureDecoder to detect the end of a TLV element and calls
 * elementListener.onReceivedElement(element) with the element.  This handles
 * the case where a single call to onReceivedData may contain multiple elements.
 * @constructor
 * @param {object} elementListener An object with an onReceivedElement method.
 */
var ElementReader = function ElementReader(elementListener)
{
  this.elementListener_ = elementListener;
  this.dataParts_ = [];
  this.tlvStructureDecoder_ = new TlvStructureDecoder();
};

exports.ElementReader = ElementReader;

/**
 * Continue to read data until the end of an element, then call
 * this.elementListener_.onReceivedElement(element). The buffer passed to
 * onReceivedElement is only valid during this call.  If you need the data
 * later, you must copy.
 * @param {Buffer} data The Buffer with the incoming element's bytes.
 */
ElementReader.prototype.onReceivedData = function(data)
{
  // Process multiple elements in the data.
  while (true) {
    var gotElementEnd;
    var offset;

    try {
      if (this.dataParts_.length === 0) {
        // This is the beginning of an element.
        if (data.length <= 0)
          // Wait for more data.
          return;
      }

      // Scan the input to check if a whole TLV element has been read.
      this.tlvStructureDecoder_.seek(0);
      gotElementEnd = this.tlvStructureDecoder_.findElementEnd(data);
      offset = this.tlvStructureDecoder_.getOffset();
    } catch (ex) {
      // Reset to read a new element on the next call.
      this.dataParts_ = [];
      this.tlvStructureDecoder_ = new TlvStructureDecoder();

      throw ex;
    }

    if (gotElementEnd) {
      // Got the remainder of an element.  Report to the caller.
      var element;
      if (this.dataParts_.length === 0)
        element = data.slice(0, offset);
      else {
        this.dataParts_.push(data.slice(0, offset));
        element = DataUtils.concatArrays(this.dataParts_);
        this.dataParts_ = [];
      }

      // Reset to read a new element. Do this before calling onReceivedElement
      // in case it throws an exception.
      data = data.slice(offset, data.length);
      this.tlvStructureDecoder_ = new TlvStructureDecoder();

      this.elementListener_.onReceivedElement(element);
      if (data.length == 0)
        // No more data in the packet.
        return;

      // else loop back to decode.
    }
    else {
      // Save a copy. We will call concatArrays later.
      var totalLength = data.length;
      for (var i = 0; i < this.dataParts_.length; ++i)
        totalLength += this.dataParts_[i].length;
      if (totalLength > NdnCommon.MAX_NDN_PACKET_SIZE) {
        // Reset to read a new element on the next call.
        this.dataParts_ = [];
        this.tlvStructureDecoder_ = new TlvStructureDecoder();

        throw new DecodingException(new Error
          ("The incoming packet exceeds the maximum limit Face.getMaxNdnPacketSize()"));
      }

      this.dataParts_.push(new Buffer(data));
      if (LOG > 3) console.log('Incomplete packet received. Length ' + data.length + '. Wait for more input.');
      return;
    }
  }
};
