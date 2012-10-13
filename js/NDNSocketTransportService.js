/* 
 * @author: ucla-cs
 * See COPYING for copyright and distribution information.
 * Implement getAsync and putAsync used by NDN using nsISocketTransportService.
 * This is used inside Firefox XPCOM modules.
 */

// Assume already imported the following:
// Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");
// Components.utils.import("resource://gre/modules/NetUtil.jsm");

/** Convert outputHex to binary, send to host:port and call hexListener.onReceivedHexData(hexData).
 */
function getAsync(host, port, outputHex, hexListener) {
	var binaryListener = {
		onReceivedData : function(data) {
			hexListener.onReceivedHexData(DataUtils.stringToHex(data));
		}
	}

    readAllFromSocket(host, port, DataUtils.hexToRawString(outputHex), binaryListener);
}

/** Send outputData to host:port, read the entire response and call listener.onReceivedData(data).
    Code derived from http://stackoverflow.com/questions/7816386/why-nsiscriptableinputstream-is-not-working .
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
		data: "",
		calledOnReceivedData: false,
		
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
			try {
				// Ignore _inputStream and use inStream.
				// Use readInputStreamToString to handle binary data.
				this.data += NetUtil.readInputStreamToString(inStream, count);
				
				// TODO: Need to parse the input to check if a whole ccnb object has been read, as in 
				// CcnbObjectReader class: https://github.com/NDN-Routing/NDNLP/blob/master/ndnld.h#L256 .
				// For now as a hack, try to fully decode this.data as a ContentObject.
				try {
 					decodeHexContentObject(DataUtils.stringToHex(this.data));
				} catch (ex) {
					// Assume the exception is because the decoder only got partial data, so read moe.
					return;
				}
				// We were able to parse the ContentObject, so finish.
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
		
		int = new Interest(new Name(message));
		int.InterestLifetime = 4200;
		var outputHex = encodeToHexInterest(int);
		
		var hexListener = {
			onReceivedHexData : function(result) {
				if (LOG>0) dump('BINARY RESPONSE IS ' + result + '\n');
				
				if (result == null || result == undefined || result =="" )
					listener.onReceivedContentObject(null);
				else {
 					var co = decodeHexContentObject(result);
					
					if(LOG>2) {
						dump('DECODED CONTENT OBJECT\n');
						dump(co);
						dump('\n');
					}
					
					listener.onReceivedContentObject(co);
				}
			}
		}
		return getAsync(this.host, this.port, outputHex, hexListener);
	}
	else {
		dump('ERROR host OR port NOT SET\n');
	}
}

