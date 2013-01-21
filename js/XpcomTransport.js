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
    this.connectedHost = null;
    this.connectedPort = null;
    
    this.defaultGetHostAndPort = NDN.makeShuffledGetHostAndPort
        (["A.hub.ndn.ucla.edu", "B.hub.ndn.ucla.edu", "C.hub.ndn.ucla.edu", "D.hub.ndn.ucla.edu", 
          "E.hub.ndn.ucla.edu", "F.hub.ndn.ucla.edu", "G.hub.ndn.ucla.edu", "H.hub.ndn.ucla.edu"],
         9695);
};

/*
 * Connect to the host and port in ndn.  This replaces a previous connection.
 * Listen on the port to read an entire binary XML encoded element and call
 *    listener.onReceivedElement(data) where data is Uint8Array.
 */
XpcomTransport.prototype.connect = function(ndn, listener) {
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
    this.connectedHost = ndn.host;
    this.connectedPort = ndn.port;
    this.outStream = this.socket.openOutputStream(1, 0, 0);

    var inStream = this.socket.openInputStream(0, 0, 0);
	var dataListener = {
		dataParts: [],
        structureDecoder: new BinaryXMLStructureDecoder(),
		
		onStartRequest: function (request, context) {
		},
		onStopRequest: function (request, context, status) {
		},
		onDataAvailable: function (request, context, _inputStream, offset, count) {
			try {
				// Use readInputStreamToString to handle binary data.
                // TODO: Can we go directly from the stream to Uint8Array?
				var rawData = DataUtils.toNumbersFromString
                    (NetUtil.readInputStreamToString(inStream, count));
				
                // Process multiple objects in this packet.
                while(true) {
                    // Scan the input to check if a whole ccnb object has been read.
                    this.structureDecoder.seek(0);
                    if (this.structureDecoder.findElementEnd(rawData)) {
                        // Got the remainder of an object.  Report to the caller.
                        this.dataParts.push(rawData.subarray(0, this.structureDecoder.offset));
                        listener.onReceivedElement(DataUtils.concatArrays(this.dataParts));
                    
                        // Need to read a new object.
                        rawData = rawData.subarray(this.structureDecoder.offset, rawData.length);
                        this.dataParts = [];
                        this.structureDecoder = new BinaryXMLStructureDecoder();
                        if (rawData.length == 0)
                            // No more data in the packet.
                            return;
                        
                        // else loop back to decode.
                    }
                    else {
                        // Save for a later call to concatArrays so that we only copy data once.
                        this.dataParts.push(rawData);
                        return;
                    }
                }
			} catch (ex) {
				console.log("XpcomTransport.onDataAvailable exception: " + ex);
			}
		}
    };
	
	pump.init(inStream, -1, -1, 0, 0, true);
    pump.asyncRead(dataListener, null);
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

XpcomTransport.prototype.expressInterest = function(ndn, interest, closure) {
    var thisXpcomTransport = this;
    
    if (this.socket == null || this.connectedHost != ndn.host || this.connectedPort != ndn.port) {
      var dataListener = {
		onReceivedElement : function(data) {
			if (data == null || data == undefined || data.length == 0)
				console.log("XpcomTransport: received empty data from socket.");
			else {
                var decoder = new BinaryXMLDecoder(data);
                if (decoder.peekStartElement(CCNProtocolDTags.Interest)) {
                    // TODO: handle interest properly.  For now, assume the only use in getting
                    //   an interest is knowing that the host is alive from NDN.ccndIdFetcher.
					var pitEntry = NDN.getEntryForExpressedInterest(NDN.ccndIdFetcher);
					if (pitEntry != null) {
						// Remove PIT entry from NDN.PITTable.
						var index = NDN.PITTable.indexOf(pitEntry);
						if (index >= 0)
							NDN.PITTable.splice(index, 1);
                        
                        pitEntry.closure.upcall(Closure.UPCALL_INTEREST, null);
                    }
                }
                else if (decoder.peekStartElement(CCNProtocolDTags.ContentObject)) {
                    var co = new ContentObject();
                    co.from_ccnb(decoder);
                   					
					var pitEntry = NDN.getEntryForExpressedInterest(co.name);
					if (pitEntry != null) {
						// Remove PIT entry from NDN.PITTable.
                        // TODO: This needs to be a single thread-safe transaction.
						var index = NDN.PITTable.indexOf(pitEntry);
						if (index >= 0)
							NDN.PITTable.splice(index, 1);
                    }
   					if (pitEntry != null) {
						var currentClosure = pitEntry.closure;
                        
                        // TODO: verify the content object and set kind to UPCALL_CONTENT.
                        var result = currentClosure.upcall(Closure.UPCALL_CONTENT_UNVERIFIED,
                                    new UpcallInfo(thisXpcomTransport.ndn, null, 0, co));
                        if (result == Closure.RESULT_OK) {
                            // success
                        }
                        else if (result == Closure.RESULT_ERR)
                            console.log("XpcomTransport: upcall returned RESULT_ERR.");
                        else if (result == Closure.RESULT_REEXPRESS) {
                            // TODO: Handl re-express interest.
                        }
                        else if (result == Closure.RESULT_VERIFY) {
                            // TODO: force verification of content.
                        }
                        else if (result == Closure.RESULT_FETCHKEY) {
                            // TODO: get the key in the key locator and re-call the interest
                            //   with the key available in the local storage.
                        }
                    }
                }
                else
                    console.log('Incoming packet is not Interest or ContentObject. Discard now.');
			}
		}
	  }
      
      this.connect(ndn, dataListener);
    }
    
    var binaryInterest = encodeToBinaryInterest(interest);
    
                        // TODO: This needs to be a single thread-safe transaction.
	var pitEntry = new PITEntry(interest, closure);
	NDN.PITTable.push(pitEntry);

    this.send(binaryInterest);
};
