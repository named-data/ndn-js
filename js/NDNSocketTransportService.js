/* 
 * @author: ucla-cs
 * See COPYING for copyright and distribution information.
 * Implement getAsync and putAsync used by NDN using nsISocketTransportService.
 * This is used inside Firefox XPCOM modules.
 */

// Assume already imported the following:
// Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");
// Components.utils.import("resource://gre/modules/NetUtil.jsm");

/** Convert outputHex to binary, send to host:port and call listener.onReceivedData(data)
 *    where data is a byte array.
 */
function getAsync(host, port, outputHex, listener) {
    readAllFromSocket(host, port, DataUtils.hexToRawString(outputHex), listener);
}

/** Send outputData to host:port, read the entire response and call listener.onReceivedData(data)
 *    where data is a byte array.
 *  Code derived from http://stackoverflow.com/questions/7816386/why-nsiscriptableinputstream-is-not-working .
 */
function readAllFromSocket(host, port, outputData, listener) {
	var transportService = Components.classes["@mozilla.org/network/socket-transport-service;1"].getService
	(Components.interfaces.nsISocketTransportService);
	var pump = Components.classes["@mozilla.org/network/input-stream-pump;1"].createInstance
	(Components.interfaces.nsIInputStreamPump);
	var transport = transportService.createTransport(null, 0, host, port, null);
	var outStream = transport.openOutputStream(1, 0, 0);
	outStream.write(outputData, outputData.length);
	outStream.flush();
	var inStream = transport.openInputStream(0, 0, 0);
	var dataListener = {
		data: [],
        structureDecoder: new BinaryXMLStructureDecoder(),
		calledOnReceivedData: false,
        debugNOnDataAvailable: 0,
		
		onStartRequest: function (request, context) {
		},
		onStopRequest: function (request, context, status) {
			inStream.close();
			outStream.close();
			if (!this.calledOnReceivedData) {
				this.calledOnReceivedData = true;
				listener.onReceivedData(this.data);
			}
		},
		onDataAvailable: function (request, context, _inputStream, offset, count) {
            if (this.calledOnReceivedData)
                // Already finished.  Ignore extra data.
                return;
            
			try {
                this.debugNOnDataAvailable += 1;
				// Ignore _inputStream and use inStream.
				// Use readInputStreamToString to handle binary data.
				var rawData = NetUtil.readInputStreamToString(inStream, count);
                this.data = this.data.concat(DataUtils.toNumbersFromString(rawData));
				
				// Scan the input to check if a whole ccnb object has been read.
                if (this.structureDecoder.findElementEnd(this.data))
                    // Finish.
                    this.onStopRequest();
			} catch (ex) {
				dump("onDataAvailable exception: " + ex + "\n");
			}
		}
    };
	
	pump.init(inStream, -1, -1, 0, 0, true);
    pump.asyncRead(dataListener, null);
}


// TODO: This should be moved to the main NDN.js when we agree on how to do non-blocking get.
// For now, assume this is included after NDN.js and modify it.
/** Encode message as an Interest, send it to host:port, read the entire response and call
      listener.onReceivedContentObject(contentObject).
 */
NDN.prototype.getAsync = function(message, listener) {
	if (this.host != null && this.port != null) {
		var output ='';
		message = message.trim();
		if(message==null || message =="" ){
			dump('INVALID INPUT TO GET\n');
			return null;
		}
		
		interest = new Interest(new Name(message));
		interest.InterestLifetime = 4200;
		var outputHex = encodeToHexInterest(interest);
		
		var dataListener = {
			onReceivedData : function(result) {
				if (result == null || result == undefined || result.length == 0)
					listener.onReceivedContentObject(null);
				else {
                    var decoder = new BinaryXMLDecoder(result);	
                    var co = new ContentObject();
                    co.from_ccnb(decoder);
					
					if(LOG>2) {
						dump('DECODED CONTENT OBJECT\n');
						dump(co);
						dump('\n');
					}
					
					listener.onReceivedContentObject(co);
				}
			}
		}
        
		return getAsync(this.host, this.port, outputHex, dataListener);
	}
	else {
		dump('ERROR host OR port NOT SET\n');
	}
}

