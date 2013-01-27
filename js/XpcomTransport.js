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
 *    elementListener.onReceivedElement(element) where element is Uint8Array.
 */
XpcomTransport.prototype.connect = function(ndn, elementListener) {
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
        elementReader: new BinaryXmlElementReader(elementListener),
		
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
    console.log("expressInterest " + interest.name.to_uri());
    var thisXpcomTransport = this;
    
    if (this.socket == null || this.connectedHost != ndn.host || this.connectedPort != ndn.port) {
      var elementListener = {
		onReceivedElement : function(element) {
            var decoder = new BinaryXMLDecoder(element);
            if (decoder.peekStartElement(CCNProtocolDTags.Interest)) {
                // TODO: handle interest properly. 
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
                        
                    // Cancel interest timer
                    clearTimeout(pitEntry.timerID);
                    
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
      
      this.connect(ndn, elementListener);
// DEBUG      this.connect(ndn, ndn);
    }
    
	//TODO: check local content store first
	if (closure != null) {
		var pitEntry = new PITEntry(interest, closure);
        // TODO: This needs to be a single thread-safe transaction on a global object.
		NDN.PITTable.push(pitEntry);
		closure.pitEntry = pitEntry;
	}

	// Set interest timer
	if (closure != null) {
		pitEntry.timerID = setTimeout(function() {
			if (LOG > 3) console.log("Interest time out.");
				
			// Remove PIT entry from NDN.PITTable.
            // TODO: Make this a thread-safe operation on the global PITTable.
			var index = NDN.PITTable.indexOf(pitEntry);
			//console.log(NDN.PITTable);
			if (index >= 0) 
	            NDN.PITTable.splice(index, 1);
			//console.log(NDN.PITTable);
			//console.log(pitEntry.interest.name.getName());
				
			// Raise closure callback
			closure.upcall(Closure.UPCALL_INTEREST_TIMED_OUT, new UpcallInfo(ndn, interest, 0, null));
		}, interest.interestLifetime);  // interestLifetime is in milliseconds.
		//console.log(closure.timerID);
	}

	this.send(encodeToBinaryInterest(interest));
};

