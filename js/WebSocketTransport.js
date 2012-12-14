/** 
 * @author: Wentao Shang
 * See COPYING for copyright and distribution information.
 */

var WebSocketTransport = function WebSocketTransport() {    
	this.ws = null;
	this.ccndid = null;
	this.maxBufferSize = 10000;  // Currently support 10000 bytes data input, consistent with BinaryXMLEncoder
	this.buffer = new Uint8Array(this.maxBufferSize);
	this.bufferOffset = 0;
	this.structureDecoder = new BinaryXMLStructureDecoder();
    this.defaultGetHostAndPort = NDN.makeShuffledGetHostAndPort
        (["A.ws.ndn.ucla.edu", "B.ws.ndn.ucla.edu", "C.ws.ndn.ucla.edu", "D.ws.ndn.ucla.edu", 
          "E.ws.ndn.ucla.edu"],
         9696);
};

WebSocketTransport.prototype.connectWebSocket = function(ndn) {
	if (this.ws != null)
		delete this.ws;
	
	this.ws = new WebSocket('ws://' + ndn.host + ':' + ndn.port);
	if (LOG > 0) console.log('ws connection created.');
	
	this.ws.binaryType = "arraybuffer";
	
	var self = this;
	this.ws.onmessage = function(ev) {
		var result = ev.data;
		//console.log('RecvHandle called.');
			
		if(result == null || result == undefined || result == "" ) {
			console.log('INVALID ANSWER');
		} else if (result instanceof ArrayBuffer) {
	        var bytearray = new Uint8Array(result);
	        
			if (LOG>3) console.log('BINARY RESPONSE IS ' + DataUtils.toHex(bytearray));
			
			try {
				if (bytearray.length + self.bufferOffset >= self.buffer.byteLength) {
					if (LOG>3) {
						console.log("NDN.ws.onmessage: buffer overflow. Accumulate received length: " + self.bufferOffset 
							+ ". Current packet length: " + bytearray.length + ".");
					}
					
					// Purge and quit.
					delete self.structureDecoder;
					delete self.buffer;
					self.structureDecoder = new BinaryXMLStructureDecoder();
					self.buffer = new Uint8Array(self.maxBufferSize);
					self.bufferOffset = 0;
					return;
				}
				
				/*for (var i = 0; i < bytearray.length; i++) {
					self.buffer.push(bytearray[i]);
				}*/
				self.buffer.set(bytearray, self.bufferOffset);
				self.bufferOffset += bytearray.length;
				
				if (!self.structureDecoder.findElementEnd(self.buffer.subarray(0, self.bufferOffset))) {
					// Need more data to decode
					if (LOG>3) console.log('Incomplete packet received. Length ' + bytearray.length + '. Wait for more input.');
					return;
				}
				if (LOG>3) console.log('Complete packet received. Length ' + bytearray.length + '. Start decoding.');
			} catch (ex) {
				console.log("NDN.ws.onmessage exception: " + ex);
				return;
			}
			
			var decoder = new BinaryXMLDecoder(self.buffer);
			// Dispatch according to packet type
			if (decoder.peekStartElement(CCNProtocolDTags.Interest)) {  // Interest packet
				if (LOG > 3) console.log('Interest packet received.');
				
				var interest = new Interest();
				interest.from_ccnb(decoder);
				if (LOG>3) console.log(interest);
				var nameStr = escape(interest.name.getName());
				if (LOG > 3) console.log(nameStr);
				
				var entry = getEntryForRegisteredPrefix(nameStr);
				if (entry != null) {
					//console.log(entry);
					entry.closure.upcall(Closure.UPCALL_INTEREST, new UpcallInfo(ndn, interest, 0, null));
				}
				
			} else if (decoder.peekStartElement(CCNProtocolDTags.ContentObject)) {  // Content packet
				if (LOG > 3) console.log('ContentObject packet received.');
				
				var co = new ContentObject();
				co.from_ccnb(decoder);
				if (LOG > 3) console.log(co);
				nameStr = co.name.getName();
				if (LOG > 3) console.log(nameStr);
				
				if (self.ccndid == null && nameStr.match(NDN.ccndIdFetcher) != null) {
					// We are in starting phase, record publisherPublicKeyDigest in self.ccndid
					if(!co.signedInfo || !co.signedInfo.publisher 
						|| !co.signedInfo.publisher.publisherPublicKeyDigest) {
						console.log("Cannot contact router, close NDN now.");
						
						// Close NDN if we fail to connect to a ccn router
						ndn.readyStatus = NDN.CLOSED;
						ndn.onclose();
						//console.log("NDN.onclose event fired.");
					} else {
						//console.log('Connected to ccnd.');
						self.ccndid = co.signedInfo.publisher.publisherPublicKeyDigest;
						if (LOG>3) console.log(self.ccndid);
						
						// Call NDN.onopen after success
						ndn.readyStatus = NDN.OPENED;
						ndn.onopen();
						//console.log("NDN.onopen event fired.");
					}
				} else {
					var pitEntry = NDN.getEntryForExpressedInterest(co.name);
					if (pitEntry != null) {
						//console.log(pitEntry);
						
						// Cancel interest timer
						clearTimeout(pitEntry.closure.timerID);
						//console.log("Clear interest timer");
						//console.log(pitEntry.closure.timerID);
						
						// Remove PIT entry from NDN.PITTable
						var index = NDN.PITTable.indexOf(pitEntry);
						if (index >= 0)
                            NDN.PITTable.splice(index, 1);
						
						// Raise callback
						pitEntry.closure.upcall(Closure.UPCALL_CONTENT, new UpcallInfo(ndn, null, 0, co));
					}
				}
			} else {
				console.log('Incoming packet is not Interest or ContentObject. Discard now.');
			}
			
			delete decoder;
			
			// Renew StrcutureDecoder and buffer after we process a full packet
			delete self.structureDecoder;
			delete self.buffer;
			self.structureDecoder = new BinaryXMLStructureDecoder();
			self.buffer = new Uint8Array(self.maxBufferSize);
			self.bufferOffset = 0;
		}
	}
	
	this.ws.onopen = function(ev) {
		if (LOG > 3) console.log(ev);
		if (LOG > 3) console.log('ws.onopen: WebSocket connection opened.');
		if (LOG > 3) console.log('ws.onopen: ReadyState: ' + this.readyState);

		// Fetch ccndid now
		var interest = new Interest(new Name(NDN.ccndIdFetcher));
		interest.interestLifetime = 4.0; // seconds
		var subarray = encodeToBinaryInterest(interest);
		
		var bytes = new Uint8Array(subarray.length);
		bytes.set(subarray);
		
		self.ws.send(bytes.buffer);
	}
	
	this.ws.onerror = function(ev) {
		console.log('ws.onerror: ReadyState: ' + this.readyState);
		console.log(ev);
		console.log('ws.onerror: WebSocket error: ' + ev.data);
	}
	
	this.ws.onclose = function(ev) {
		console.log('ws.onclose: WebSocket connection closed.');
		self.ws = null;
		
		// Close NDN when WebSocket is closed
		ndn.readyStatus = NDN.CLOSED;
		ndn.onclose();
		//console.log("NDN.onclose event fired.");
	}
};

WebSocketTransport.prototype.expressInterest = function(ndn, interest, closure) {
	if (this.ws != null) {
		//TODO: check local content store first

        var binaryInterest = encodeToBinaryInterest(interest);
		var bytearray = new Uint8Array(binaryInterest.length);
		bytearray.set(binaryInterest);
		
		var pitEntry = new PITEntry(interest, closure);
		NDN.PITTable.push(pitEntry);
		
		this.ws.send(bytearray.buffer);
		if (LOG > 3) console.log('ws.send() returned.');
		
		// Set interest timer
		closure.timerID = setTimeout(function() {
			if (LOG > 3) console.log("Interest time out.");
			
			// Remove PIT entry from NDN.PITTable
			var index = NDN.PITTable.indexOf(pitEntry);
			//console.log(NDN.PITTable);
			if (index >= 0) 
                NDN.PITTable.splice(index, 1);
			//console.log(NDN.PITTable);
			// Raise closure callback
			closure.upcall(Closure.UPCALL_INTEREST_TIMED_OUT, new UpcallInfo(ndn, interest, 0, null));
		}, interest.interestLifetime * 1000);  // convert interestLifetime from seconds to ms.
		//console.log(closure.timerID);
	}
	else
		console.log('WebSocket connection is not established.');
};


// For publishing data
var CSTable = new Array();

var CSEntry = function CSEntry(name, closure) {
	this.name = name;        // String
	this.closure = closure;  // Closure
};

function getEntryForRegisteredPrefix(name) {
	for (var i = 0; i < CSTable.length; i++) {
		if (CSTable[i].name.match(name) != null)
			return CSTable[i];
	}
	return null;
}

WebSocketTransport.prototype.registerPrefix = function(ndn, name, closure, flag) {
	if (this.ws != null) {
		if (this.ccndid == null) {
			console.log('ccnd node ID unkonwn. Cannot register prefix.');
			return -1;
		}
		
		var fe = new ForwardingEntry('selfreg', name, null, null, 3, 2147483647);
		var bytes = encodeForwardingEntry(fe);
		
		var si = new SignedInfo();
		si.setFields();
		
		var co = new ContentObject(new Name(), si, bytes, new Signature()); 
		co.sign();
		var coBinary = encodeToBinaryContentObject(co);
		
		//var nodename = unescape('%00%88%E2%F4%9C%91%16%16%D6%21%8E%A0c%95%A5%A6r%11%E0%A0%82%89%A6%A9%85%AB%D6%E2%065%DB%AF');
		var nodename = this.ccndid;
		var interestName = new Name(['ccnx', nodename, 'selfreg', coBinary]);

		var interest = new Interest(interestName);
		interest.scope = 1;
		var binaryInterest = encodeToBinaryInterest(interest);
		// If we directly use binaryInterest.buffer to feed ws.send(), 
		// WebSocket will end up sending a packet with 10000 bytes of data.
		// That is, WebSocket will flush the entire buffer in BinaryXMLEncoder
		// regardless of the offset of the Uint8Array. So we have to create
		// a new Uint8Array buffer with just the right size and copy the 
		// content from binaryInterest to the new buffer.
		//    ---Wentao
    	var bytearray = new Uint8Array(binaryInterest.length);
		bytearray.set(binaryInterest);
		if (LOG > 3) console.log('Send Interest registration packet.');
    	
    	var csEntry = new CSEntry(name.getName(), closure);
		CSTable.push(csEntry);
    	
    	this.ws.send(bytearray.buffer);
		
		return 0;
	} else {
		console.log('WebSocket connection is not established.');
		return -1;
	}
};

