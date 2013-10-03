/**
 * @author: Jeff Thompson
 * See COPYING for copyright and distribution information.
 */

var DataUtils = require('../encoding/DataUtils.js').DataUtils;
var BinaryXMLStructureDecoder = require('../encoding/BinaryXMLStructureDecoder.js').BinaryXMLStructureDecoder;
var LOG = require('../Log.js').Log.LOG;

/**
 * A BinaryXmlElementReader lets you call onReceivedData multiple times which uses a
 * BinaryXMLStructureDecoder to detect the end of a binary XML element and calls
 * elementListener.onReceivedElement(element) with the element. 
 * This handles the case where a single call to onReceivedData may contain multiple elements.
 * @constructor
 * @param {{onReceivedElement:function}} elementListener
 */
var BinaryXmlElementReader = function BinaryXmlElementReader(elementListener) {
  this.elementListener = elementListener;
	this.dataParts = [];
  this.structureDecoder = new BinaryXMLStructureDecoder();
};

exports.BinaryXmlElementReader = BinaryXmlElementReader;

BinaryXmlElementReader.prototype.onReceivedData = function(/* Buffer */ data) {
    // Process multiple objects in the data.
    while(true) {
        // Scan the input to check if a whole ndnb object has been read.
        this.structureDecoder.seek(0);
        if (this.structureDecoder.findElementEnd(data)) {
            // Got the remainder of an object.  Report to the caller.
            this.dataParts.push(data.slice(0, this.structureDecoder.offset));
            var element = DataUtils.concatArrays(this.dataParts);
            this.dataParts = [];
            try {
                this.elementListener.onReceivedElement(element);
            } catch (ex) {
                console.log("BinaryXmlElementReader: ignoring exception from onReceivedElement: " + ex);
            }
        
            // Need to read a new object.
            data = data.slice(this.structureDecoder.offset, data.length);
            this.structureDecoder = new BinaryXMLStructureDecoder();
            if (data.length == 0)
                // No more data in the packet.
                return;
            
            // else loop back to decode.
        }
        else {
            // Save for a later call to concatArrays so that we only copy data once.
            this.dataParts.push(data);
            if (LOG>3) console.log('Incomplete packet received. Length ' + data.length + '. Wait for more input.');
                return;
        }
    }    
};
