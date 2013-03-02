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
    this.ndn = null;
    this.socket = null; // nsISocketTransport
    this.outStream = null;
    this.connectedHost = null; // Read by NDN.
    this.connectedPort = null; // Read by NDN.
    
    this.defaultGetHostAndPort = NDN.makeShuffledGetHostAndPort
        (["A.hub.ndn.ucla.edu", "B.hub.ndn.ucla.edu", "C.hub.ndn.ucla.edu", "D.hub.ndn.ucla.edu", 
          "E.hub.ndn.ucla.edu", "F.hub.ndn.ucla.edu", "G.hub.ndn.ucla.edu", "H.hub.ndn.ucla.edu"],
         9695);
};

/*
 * Connect to the host and port in ndn.  This replaces a previous connection and sets connectedHost
 *   and connectedPort.  Once connected, call onopenCallback().
 * Listen on the port to read an entire binary XML encoded element and call
 *    ndn.onReceivedElement(element).
 */
XpcomTransport.prototype.connect = function(ndn, onopenCallback) {
    if (this.socket != null) {
        try {
            this.socket.close(0);
        } catch (ex) {
			console.log("XpcomTransport socket.close exception: " + ex);
		}
        this.socket = null;
    }
    this.ndn = ndn;

	var transportService = Components.classes["@mozilla.org/network/socket-transport-service;1"].getService
        (Components.interfaces.nsISocketTransportService);
	var pump = Components.classes["@mozilla.org/network/input-stream-pump;1"].createInstance
        (Components.interfaces.nsIInputStreamPump);
	this.socket = transportService.createTransport(null, 0, ndn.host, ndn.port, null);
    if (LOG > 0) console.log('XpcomTransport: Connected to ' + ndn.host + ":" + ndn.port);
    this.connectedHost = ndn.host;
    this.connectedPort = ndn.port;
    this.outStream = this.socket.openOutputStream(1, 0, 0);

    var inStream = this.socket.openInputStream(0, 0, 0);
	var dataListener = {
        elementReader: new BinaryXmlElementReader(ndn),
		
		onStartRequest: function (request, context) {
		},
		onStopRequest: function (request, context, status) {
		},
		onDataAvailable: function (request, context, _inputStream, offset, count) {
			try {
				// Use readInputStreamToString to handle binary data.
                // TODO: Can we go directly from the stream to Uint8Array?
                this.elementReader.onReceivedData(DataUtils.toNumbersFromString
                    (NetUtil.readInputStreamToString(inStream, count)));
			} catch (ex) {
				console.log("XpcomTransport.onDataAvailable exception: " + ex + "\n" + ex.stack);
			}
		}
    };
	
	pump.init(inStream, -1, -1, 0, 0, true);
    pump.asyncRead(dataListener, null);
    
    onopenCallback();
};

/*
 * Send the data over the connection created by connect.
 */
XpcomTransport.prototype.send = function(/* Uint8Array */ data) {
    if (this.socket == null) {
        console.log("XpcomTransport connection is not established.");
        return;
    }
    
    var rawDataString = DataUtils.toString(data);
	this.outStream.write(rawDataString, rawDataString.length);
	this.outStream.flush();
};
