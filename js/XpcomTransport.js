/** 
 * @author: Jeff Thompson
 * See COPYING for copyright and distribution information.
 * Implement getAsync and putAsync used by NDN using nsISocketTransportService.
 * This is used inside Firefox XPCOM modules.
 */

// Assume already imported the following:
// Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");
// Components.utils.import("resource://gre/modules/NetUtil.jsm");

var XpcomTransport = function XpcomTransport() {    
};

XpcomTransport.prototype.expressInterest = function(ndn, interest, closure) {
    var binaryInterest = encodeToBinaryInterest(interest);
    
    var dataListener = {
		onReceivedData : function(data) {
			if (data == null || data == undefined || data.length == 0)
				dump("NDN.expressInterest: received empty data from socket.\n");
			else {
                var decoder = new BinaryXMLDecoder(data);	
                var co = new ContentObject();
                co.from_ccnb(decoder);
                   					
                // TODO: verify the content object and set kind to UPCALL_CONTENT.
				var result = closure.upcall(Closure.UPCALL_CONTENT_UNVERIFIED,
                               new UpcallInfo(ndn, interest, 0, co));
                if (result == Closure.RESULT_OK) {
                    // success
                }
                else if (result == Closure.RESULT_ERR)
                    dump("NDN.expressInterest: upcall returned RESULT_ERR.\n");
                else if (result == Closure.RESULT_REEXPRESS)
                    XpcomTransport.readAllFromSocket(ndn.host, ndn.port, binaryInterest, dataListener);
                else if (result == Closure.RESULT_VERIFY) {
                    // TODO: force verification of content.
                }
                else if (result == Closure.RESULT_FETCHKEY) {
                    // TODO: get the key in the key locator and re-call the interest
                    //   with the key available in the local storage.
                }
			}
		}
	}    
    
	XpcomTransport.readAllFromSocket(ndn.host, ndn.port, binaryInterest, dataListener);
};

/** Send outputData (Uint8Array) to host:port, read the entire response and call 
 *    listener.onReceivedData(data) where data is Uint8Array.
 *  Code derived from http://stackoverflow.com/questions/7816386/why-nsiscriptableinputstream-is-not-working .
 */
XpcomTransport.readAllFromSocket = function(host, port, outputData, listener) {
	var transportService = Components.classes["@mozilla.org/network/socket-transport-service;1"].getService
        (Components.interfaces.nsISocketTransportService);
	var pump = Components.classes["@mozilla.org/network/input-stream-pump;1"].createInstance
        (Components.interfaces.nsIInputStreamPump);
	var transport = transportService.createTransport(null, 0, host, port, null);
	var outStream = transport.openOutputStream(1, 0, 0);
    var rawDataString = DataUtils.toString(outputData);
	outStream.write(rawDataString, rawDataString.length);
	outStream.flush();
	var inStream = transport.openInputStream(0, 0, 0);
	var dataListener = {
		dataParts: [],
        structureDecoder: new BinaryXMLStructureDecoder(),
		calledOnReceivedData: false,
		
		onStartRequest: function (request, context) {
		},
		onStopRequest: function (request, context, status) {
			inStream.close();
			outStream.close();
			if (!this.calledOnReceivedData) {
				this.calledOnReceivedData = true;
				listener.onReceivedData(DataUtils.concatArrays(this.dataParts));
			}
		},
		onDataAvailable: function (request, context, _inputStream, offset, count) {
            if (this.calledOnReceivedData)
                // Already finished.  Ignore extra data.
                return;
            
			try {
				// Ignore _inputStream and use inStream.
				// Use readInputStreamToString to handle binary data.
                // TODO: Can we go directly from the stream to Uint8Array?
				var rawData = DataUtils.toNumbersFromString
                    (NetUtil.readInputStreamToString(inStream, count));
                // Save for later call to concatArrays so that we only reallocate a buffer once.
                this.dataParts.push(rawData);
				
				// Scan the input to check if a whole ccnb object has been read.
                this.structureDecoder.seek(0);
                if (this.structureDecoder.findElementEnd(rawData))
                    // Finish.
                    this.onStopRequest();
			} catch (ex) {
				dump("readAllFromSocket.onDataAvailable exception: " + ex + "\n");
			}
		}
    };
	
	pump.init(inStream, -1, -1, 0, 0, true);
    pump.asyncRead(dataListener, null);
}

