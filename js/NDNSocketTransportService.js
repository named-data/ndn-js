/* 
 * @author: ucla-cs
 * See COPYING for copyright and distribution information.
 * Implement getAsync and putAsync used by NDN using nsISocketTransportService.
 * This is used inside Firefox XPCOM modules.
 */

// Assume already imported the following:
// Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");
// Components.utils.import("resource://gre/modules/NetUtil.jsm");

/** Send outputData (byte array) to host:port, read the entire response and call 
 *    listener.onReceivedData(data) where data is a byte array.
 *  Code derived from http://stackoverflow.com/questions/7816386/why-nsiscriptableinputstream-is-not-working .
 */
function readAllFromSocket(host, port, outputData, listener) {
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
		data: [],
        structureDecoder: new BinaryXMLStructureDecoder(),
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
            if (this.calledOnReceivedData)
                // Already finished.  Ignore extra data.
                return;
            
			try {
				// Ignore _inputStream and use inStream.
				// Use readInputStreamToString to handle binary data.
				var rawData = NetUtil.readInputStreamToString(inStream, count);
                this.data = this.data.concat(DataUtils.toNumbersFromString(rawData));
				
				// Scan the input to check if a whole ccnb object has been read.
                if (this.structureDecoder.findElementEnd(this.data))
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

