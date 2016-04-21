/**
 * Copyright (C) 2013-2016 Regents of the University of California.
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
 * @param {{onReceivedElement:function}} elementListener
 */
var ElementReader = function ElementReader(elementListener)
{
  this.elementListener = elementListener;
  this.dataParts = [];
  this.tlvStructureDecoder = new TlvStructureDecoder();
};

exports.ElementReader = ElementReader;

ElementReader.prototype.onReceivedData = function(/* Buffer */ data)
{
  // Process multiple objects in the data.
  while (true) {
    var gotElementEnd;
    var offset;

    try {
      if (this.dataParts.length == 0) {
        // This is the beginning of an element.
        if (data.length <= 0)
          // Wait for more data.
          return;
      }

      // Scan the input to check if a whole TLV object has been read.
      this.tlvStructureDecoder.seek(0);
      gotElementEnd = this.tlvStructureDecoder.findElementEnd(data);
      offset = this.tlvStructureDecoder.getOffset();
    } catch (ex) {
      // Reset to read a new element on the next call.
      this.dataParts = [];
      this.tlvStructureDecoder = new TlvStructureDecoder();

      throw ex;
    }

    if (gotElementEnd) {
      // Got the remainder of an object.  Report to the caller.
      this.dataParts.push(data.slice(0, offset));
      var element = DataUtils.concatArrays(this.dataParts);
      this.dataParts = [];

      // Reset to read a new object. Do this before calling onReceivedElement
      // in case it throws an exception.
      data = data.slice(offset, data.length);
      this.tlvStructureDecoder = new TlvStructureDecoder();

      this.elementListener.onReceivedElement(element);
      if (data.length == 0)
        // No more data in the packet.
        return;

      // else loop back to decode.
    }
    else {
      // Save a copy. We will call concatArrays later.
      var totalLength = data.length;
      for (var i = 0; i < this.dataParts.length; ++i)
        totalLength += this.dataParts[i].length;
      if (totalLength > NdnCommon.MAX_NDN_PACKET_SIZE) {
        // Reset to read a new element on the next call.
        this.dataParts = [];
        this.tlvStructureDecoder = new TlvStructureDecoder();

        throw new DecodingException(new Error
          ("The incoming packet exceeds the maximum limit Face.getMaxNdnPacketSize()"));
      }

      this.dataParts.push(new Buffer(data));
      if (LOG > 3) console.log('Incomplete packet received. Length ' + data.length + '. Wait for more input.');
        return;
    }
  }
};
