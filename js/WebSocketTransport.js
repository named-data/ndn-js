/* 
 * @author: Wentao Shang
 * See COPYING for copyright and distribution information.
 * Implement getAsync and putAsync used by NDN using nsISocketTransportService.
 * This is used inside Firefox XPCOM modules.
 */

var WebSocketTransport = function WebSocketTransport() {    
	this.ws = null;
	this.ccndid = null;
	this.maxBufferSize = 10000;  // Currently support 10000 bytes data input, consistent with BinaryXMLEncoder
	this.buffer = new Uint8Array(this.maxBufferSize);
	this.structureDecoder = new BinaryXMLStructureDecoder();
};

WebSocketTransport.prototype.expressInterest = function(ndn, interest, closure) {
	if (this.ws != null) {
		//TODO: check local content store first

        var binaryInterest = encodeToBinaryInterest(interest);
		var bytearray = new Uint8Array(binaryInterest.length);
		bytearray.set(binaryInterest);
		
		var pitEntry = new PITEntry(interest.name.getName(), closure);
		PITTable.push(pitEntry);
		
		this.ws.send(bytearray.buffer);
		console.log('ws.send() returned.');
	}
	else{
		console.log('WebSocket connection is not established.');
		return null;
	}
};


var ccndIdFetcher = '/%C1.M.S.localhost/%C1.M.SRV/ccnd/KEY';

WebSocketTransport.prototype.connectWebSocket = function(ndn) {
	if (this.ws != null)
		delete this.ws;
	
	this.ws = new WebSocket('ws://' + ndn.host + ':' + ndn.port);
	console.log('ws connection created.');
	
	this.ws.binaryType = "arraybuffer";
	
	var self = this;
	this.ws.onmessage = function(ev) {
		var result = ev.data;
		//console.log('RecvHandle called.');
			
		if(result == null || result == undefined || result == "" ) {
			console.log('INVALID ANSWER');
		} else if (result instanceof ArrayBuffer) {
	        var bytearray = new Uint8Array(result);
	        
			if (LOG>3) console.log('BINARY RESPONSE IS ' + bytearray);
			
			try {
				if (bytearray.length + self.buffer.byteOffset >= self.buffer.byteLength) {
					console.log("NDN.ws.onmessage: buffer overflow. Accumulate received length: " + self.buffer.byteOffset 
						+ ". Current packet length: " + bytearray.length + ".");
					// Purge and quit.
					delete self.structureDecoder;
					delete self.buffer;
					self.structureDecoder = new BinaryXMLStructureDecoder();
					self.buffer = new Uint8Array(self.maxBufferSize);
					return;
				}
				
				/*for (var i = 0; i < bytearray.length; i++) {
					self.buffer.push(bytearray[i]);
				}*/
				self.buffer.set(bytearray, self.buffer.byteOffset);
				
				if (!self.structureDecoder.findElementEnd(self.buffer)) {
					// Need more data to decode
					console.log('Incomplete packet received. Length ' + bytearray.length + '. Wait for more input.');
					console.log('self.buffer length: ' + self.buffer.length);
					return;
				}
			} catch (ex) {
				console.log("NDN.ws.onmessage exception: " + ex);
				return;
			}
			
			var decoder = new BinaryXMLDecoder(self.buffer);
			// Dispatch according to packet type
			if (decoder.peekStartElement(CCNProtocolDTags.Interest)) {  // Interest packet
				console.log('Interest packet received.');
				
				var interest = new Interest();
				interest.from_ccnb(decoder);
				if (LOG>3) console.log(interest);
				var nameStr = escape(interest.name.getName());
				console.log(nameStr);
				
				var entry = getEntryForRegisteredPrefix(nameStr);
				if (entry != null) {
					//console.log(entry);
					entry.closure.upcall(Closure.UPCALL_INTEREST, new UpcallInfo(ndn, interest, 0, null));
				}
				
			} else if (decoder.peekStartElement(CCNProtocolDTags.ContentObject)) {  // Content packet
				console.log('ContentObject packet received.');
				
				var co = new ContentObject();
				co.from_ccnb(decoder);
				if (LOG>3) console.log(co);
				nameStr = co.name.getName();
				console.log(nameStr);
				
				if (self.ccndid == null && nameStr.match(ccndIdFetcher) != null) {
					// We are in starting phase, record publisherPublicKeyDigest in self.ccndid
					if(!co.signedInfo || !co.signedInfo.publisher 
						|| !co.signedInfo.publisher.publisherPublicKeyDigest) {
						console.log("Cannot contact router");
					} else {
						console.log('Connected to ccnd.');
						self.ccndid = co.signedInfo.publisher.publisherPublicKeyDigest;
						if (LOG>3) console.log(self.ccndid);
					}
				} else {
					var pitEntry = getEntryForExpressedInterest(nameStr);
					if (pitEntry != null) {
						//console.log(pitEntry);
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
		}
	}
	
	this.ws.onopen = function(ev) {
		console.log(ev);
		console.log('ws.onopen: WebSocket connection opened.');
		console.log('ws.onopen: ReadyState: ' + this.readyState);

		// Fetch ccndid now
		interest = new Interest(new Name(ccndIdFetcher));
		interest.InterestLifetime = 4200;
		//var hex = encodeToHexInterest(interest);
		var hex = encodeToBinaryInterest(interest);
		
		/*var bytes = new Uint8Array(hex.length / 2);
		for (var i = 0; i < hex.length; i = i + 2) {
	    	bytes[i / 2] = '0x' + hex.substr(i, 2);
		}*/
		var bytes = new Uint8Array(hex.length);
		bytes.set(hex);
		
		self.ws.send(bytes.buffer);
		console.log('ws.onopen: ws.send() returned.');
	}
	
	this.ws.onerror = function(ev) {
		console.log('ws.onerror: ReadyState: ' + this.readyState);
		console.log(ev);
		console.log('ws.onerror: WebSocket error: ' + ev.data);
	}
	
	this.ws.onclose = function(ev) {
		console.log('ws.onclose: WebSocket connection closed.');
		self.ws = null;
	}
}


// For fetching data
var PITTable = new Array();

var PITEntry = function PITEntry(interest, closure) {
	this.interest = interest;  // String
	this.closure = closure;    // Closure
}

function getEntryForExpressedInterest(name) {
	for (var i = 0; i < PITTable.length; i++) {
		if (name.match(PITTable[i].interest) != null)
			return PITTable[i];
			// TODO: handle multiple matching prefixes
	}
	return null;
}


// For publishing data
var CSTable = new Array();

var CSEntry = function CSEntry(name, closure) {
	this.name = name;        // String
	this.closure = closure;  // Closure
}

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
			return;
		}
		
		var fe = new ForwardingEntry('selfreg', name, null, null, 3, 2147483647);
		var bytes = encodeForwardingEntry(fe);
		
		var si = new SignedInfo();
		si.setFields();
		
		var co = new ContentObject(new Name(), si, bytes, new Signature()); 
		co.sign();
		var coBinary = encodeToBinaryContentObject(co);
		
		//var ccnxnodename = unescape('%00%88%E2%F4%9C%91%16%16%D6%21%8E%A0c%95%A5%A6r%11%E0%A0%82%89%A6%A9%85%AB%D6%E2%065%DB%AF');
		var ccnxnodename = this.ccndid;
		var interestName = new Name(['ccnx', ccnxnodename, 'selfreg', coBinary]);

		var interest = new Interest(interestName);
		interest.scope = 1;
		//var hex = encodeToHexInterest(int);
		var binaryInterest = encodeToBinaryInterest(interest);
    	var bytearray = new Uint8Array(binaryInterest.length);
		bytearray.set(binaryInterest);
		console.log('Send Interest registration packet.');
    	
    	var csEntry = new CSEntry(name.getName(), closure);
		CSTable.push(csEntry);
    	
    	this.ws.send(bytearray.buffer);
		console.log('ws.send() returned.');
		
		return 0;
	} else {
		console.log('WebSocket connection is not established.');
		return -1;
	}
}

