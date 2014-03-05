/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

var DataUtils = require('./data-utils.js').DataUtils;
var BinaryXMLStructureDecoder = require('./binary-xml-structure-decoder.js').BinaryXMLStructureDecoder;
var Tlv = require('./tlv/tlv.js').Tlv;
var TlvStructureDecoder = require('./tlv/tlv-structure-decoder.js').TlvStructureDecoder;
var LOG = require('../log.js').Log.LOG;

/**
 * A ElementReader lets you call onReceivedData multiple times which uses a
 * BinaryXMLStructureDecoder or TlvStructureDecoder to detect the end of a 
 * binary XML or TLV element and calls elementListener.onReceivedElement(element) 
 * with the element.  This handles the case where a single call to 
 * onReceivedData may contain multiple elements.
 * @constructor
 * @param {{onReceivedElement:function}} elementListener
 */
var ElementReader = function ElementReader(elementListener) 
{
  this.elementListener = elementListener;
  this.dataParts = [];
  this.binaryXmlStructureDecoder = new BinaryXMLStructureDecoder();
  this.tlvStructureDecoder = new TlvStructureDecoder();
  this.useTlv = null;
};

exports.ElementReader = ElementReader;

ElementReader.prototype.onReceivedData = function(/* Buffer */ data) 
{
  // Process multiple objects in the data.
  while (true) {
    if (this.dataParts.length == 0) {
      // This is the beginning of an element.  Check whether it is binaryXML or TLV.
      if (data.length <= 0)
        // Wait for more data.
        return;
      
      // The type codes for TLV Interest and Data packets are chosen to not
      //   conflict with the first byte of a binary XML packet, so we can
      //   just look at the first byte.
      if (data[0] == Tlv.Interest || data[0] == Tlv.Data || data[0] == 0x80)
        this.useTlv = true;
      else
        // Binary XML.
        this.useTlv = false;
    }

    var gotElementEnd;
    var offset;
    if (this.useTlv) {
      // Scan the input to check if a whole TLV object has been read.
      this.tlvStructureDecoder.seek(0);
      gotElementEnd = this.tlvStructureDecoder.findElementEnd(data);
      offset = this.tlvStructureDecoder.getOffset();
    }
    else {
      // Scan the input to check if a whole Binary XML object has been read.
      this.binaryXmlStructureDecoder.seek(0);
      gotElementEnd = this.binaryXmlStructureDecoder.findElementEnd(data);
      offset = this.binaryXmlStructureDecoder.offset;
    }
    
    if (gotElementEnd) {
      // Got the remainder of an object.  Report to the caller.
      this.dataParts.push(data.slice(0, offset));
      var element = DataUtils.concatArrays(this.dataParts);
      this.dataParts = [];
      try {
        this.elementListener.onReceivedElement(element);
      } catch (ex) {
          console.log("ElementReader: ignoring exception from onReceivedElement: " + ex);
      }
  
      // Need to read a new object.
      data = data.slice(offset, data.length);
      this.binaryXmlStructureDecoder = new BinaryXMLStructureDecoder();
      this.tlvStructureDecoder = new TlvStructureDecoder();
      if (data.length == 0)
        // No more data in the packet.
        return;
      
      // else loop back to decode.
    }
    else {
      // Save for a later call to concatArrays so that we only copy data once.
      this.dataParts.push(data);
      if (LOG > 3) console.log('Incomplete packet received. Length ' + data.length + '. Wait for more input.');
        return;
    }
  }    
};
