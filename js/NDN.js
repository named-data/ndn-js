/**
 * @author: Meki Cherkaoui, Jeff Thompson, Wentao Shang
 * See COPYING for copyright and distribution information.
 * This class represents the top-level object for communicating with an NDN host.
 */

var LOG = 0;

/**
 * settings is an associative array with the following defaults:
 * {
 *   getTransport: function() { return new WebSocketTransport(); },
 *   getHostAndPort: transport.defaultGetHostAndPort,
 *   host: null, // If null, use getHostAndPort when connecting.
 *   port: 9696,
 *   onopen: function() { if (LOG > 3) console.log("NDN connection established."); },
 *   onclose: function() { if (LOG > 3) console.log("NDN connection closed."); },
 *   verify: true // If false, don't verify and call upcall with Closure.UPCALL_CONTENT_UNVERIFIED.
 * }
 * 
 * getHostAndPort is a function, on each call it returns a new { host: host, port: port } or
 *   null if there are no more hosts.
 *   
 * This throws an exception if NDN.supported is false.
 */
var NDN = function NDN(settings) {
    if (!NDN.supported)
        throw new Error("The necessary JavaScript support is not available on this platform.");
    
    settings = (settings || {});
    var getTransport = (settings.getTransport || function() { return new WebSocketTransport(); });
    this.transport = getTransport();
    this.getHostAndPort = (settings.getHostAndPort || this.transport.defaultGetHostAndPort);
	this.host = (settings.host !== undefined ? settings.host : null);
	this.port = (settings.port || 9696);
    this.readyStatus = NDN.UNOPEN;
    this.verify = (settings.verify !== undefined ? settings.verify : true);
    // Event handler
    this.onopen = (settings.onopen || function() { if (LOG > 3) console.log("NDN connection established."); });
    this.onclose = (settings.onclose || function() { if (LOG > 3) console.log("NDN connection closed."); });
	this.ccndid = null;
};

NDN.UNOPEN = 0;  // created but not opened yet
NDN.OPENED = 1;  // connection to ccnd opened
NDN.CLOSED = 2;  // connection to ccnd closed

/*
 * Return true if necessary JavaScript support is available, else log an error and return false.
 */
NDN.getSupported = function() {
    try {
        var dummy = new Uint8Array(1).subarray(0, 1);
    } catch (ex) {
        console.log("NDN not available: Uint8Array not supported. " + ex);
        return false;
    }
    
    return true;
};

NDN.supported = NDN.getSupported();

NDN.ccndIdFetcher = new Name('/%C1.M.S.localhost/%C1.M.SRV/ccnd/KEY');

NDN.prototype.createRoute = function(host, port) {
	this.host=host;
	this.port=port;
};


NDN.KeyStore = new Array();

var KeyStoreEntry = function KeyStoreEntry(name, rsa, time) {
	this.keyName = name;  // KeyName
	this.rsaKey = rsa;    // RSA key
	this.timeStamp = time;  // Time Stamp
};

NDN.addKeyEntry = function(/* KeyStoreEntry */ keyEntry) {
	var result = NDN.getKeyByName(keyEntry.keyName);
	if (result == null) 
		NDN.KeyStore.push(keyEntry);
	else
		result = keyEntry;
};

NDN.getKeyByName = function(/* KeyName */ name) {
	var result = null;
	
	for (var i = 0; i < NDN.KeyStore.length; i++) {
		if (NDN.KeyStore[i].keyName.contentName.match(name.contentName)) {
            if (result == null || 
                NDN.KeyStore[i].keyName.contentName.components.length > result.keyName.contentName.components.length)
                result = NDN.KeyStore[i];
        }
	}
    
	return result;
};

// For fetching data
NDN.PITTable = new Array();

var PITEntry = function PITEntry(interest, closure) {
	this.interest = interest;  // Interest
	this.closure = closure;    // Closure
	this.timerID = -1;  // Timer ID
};

/*
 * Return the entry from NDN.PITTable where the name conforms to the interest selectors, and
 * the interest name is the longest that matches name.
 */
NDN.getEntryForExpressedInterest = function(/*Name*/ name) {
    var result = null;
    
	for (var i = 0; i < NDN.PITTable.length; i++) {
		if (NDN.PITTable[i].interest.matches_name(name)) {
            if (result == null || 
                NDN.PITTable[i].interest.name.components.length > result.interest.name.components.length)
                result = NDN.PITTable[i];
        }
	}
    
	return result;
};

// For publishing data
NDN.CSTable = new Array();

var CSEntry = function CSEntry(name, closure) {
	this.name = name;        // String
	this.closure = closure;  // Closure
};

function getEntryForRegisteredPrefix(name) {
	for (var i = 0; i < NDN.CSTable.length; i++) {
		if (NDN.CSTable[i].name.match(name) != null)
			return NDN.CSTable[i];
	}
	return null;
}

/*
 * Return a function that selects a host at random from hostList and returns { host: host, port: port }.
 * If no more hosts remain, return null.
 */
NDN.makeShuffledGetHostAndPort = function(hostList, port) {
    // Make a copy.
    hostList = hostList.slice(0, hostList.length);
    DataUtils.shuffle(hostList);

    return function() {
        if (hostList.length == 0)
            return null;
        
        return { host: hostList.splice(0, 1)[0], port: port };
    };
};

/** Encode name as an Interest. If template is not null, use its attributes.
 *  Send the interest to host:port, read the entire response and call
 *  closure.upcall(Closure.UPCALL_CONTENT (or Closure.UPCALL_CONTENT_UNVERIFIED),
 *                 new UpcallInfo(this, interest, 0, contentObject)).                 
 */
NDN.prototype.expressInterest = function(
        // Name
        name,
        // Closure
        closure,
        // Interest
        template) {
	var interest = new Interest(name);
    if (template != null) {
		interest.minSuffixComponents = template.minSuffixComponents;
		interest.maxSuffixComponents = template.maxSuffixComponents;
		interest.publisherPublicKeyDigest = template.publisherPublicKeyDigest;
		interest.exclude = template.exclude;
		interest.childSelector = template.childSelector;
		interest.answerOriginKind = template.answerOriginKind;
		interest.scope = template.scope;
		interest.interestLifetime = template.interestLifetime;
    }
    else
        interest.interestLifetime = 4000;   // default interest timeout value in milliseconds.

	if (this.host == null || this.port == null) {
        if (this.getHostAndPort == null)
            console.log('ERROR: host OR port NOT SET');
        else {
            var thisNDN = this;
            this.connectAndExecute
                (function() { thisNDN.reconnectAndExpressInterest(interest, closure); });
        }
    }
    else
        this.reconnectAndExpressInterest(interest, closure);
};

/*
 * If the host and port are different than the ones in this.transport, then call
 *   this.transport.connect to change the connection (or connect for the first time).
 * Then call expressInterestHelper.
 */
NDN.prototype.reconnectAndExpressInterest = function(interest, closure) {
    if (this.transport.connectedHost != this.host || this.transport.connectedPort != this.port) {
        var thisNDN = this;
        this.transport.connect(thisNDN, function() { thisNDN.expressInterestHelper(interest, closure); });
    }
    else
        this.expressInterestHelper(interest, closure);
};

/*
 * Do the work of reconnectAndExpressInterest once we know we are connected.  Set the PITTable and call
 *   this.transport.send to send the interest.
 */
NDN.prototype.expressInterestHelper = function(interest, closure) {
    var binaryInterest = encodeToBinaryInterest(interest);
    var thisNDN = this;    
	//TODO: check local content store first
	if (closure != null) {
		var pitEntry = new PITEntry(interest, closure);
        // TODO: This needs to be a single thread-safe transaction on a global object.
		NDN.PITTable.push(pitEntry);
		closure.pitEntry = pitEntry;

        // Set interest timer.
        var timeoutMilliseconds = (interest.interestLifetime || 4000);
        var timeoutCallback = function() {
			if (LOG > 1) console.log("Interest time out: " + interest.name.to_uri());
				
			// Remove PIT entry from NDN.PITTable, even if we add it again later to re-express
            //   the interest because we don't want to match it in the mean time.
            // TODO: Make this a thread-safe operation on the global PITTable.
			var index = NDN.PITTable.indexOf(pitEntry);
			if (index >= 0) 
	            NDN.PITTable.splice(index, 1);
				
			// Raise closure callback
			if (closure.upcall(Closure.UPCALL_INTEREST_TIMED_OUT, 
                  new UpcallInfo(thisNDN, interest, 0, null)) == Closure.RESULT_REEXPRESS) {
			    if (LOG > 1) console.log("Re-express interest: " + interest.name.to_uri());
                pitEntry.timerID = setTimeout(timeoutCallback, timeoutMilliseconds);
                NDN.PITTable.push(pitEntry);
                thisNDN.transport.send(binaryInterest);
            }
		};
		pitEntry.timerID = setTimeout(timeoutCallback, timeoutMilliseconds);
	}

	this.transport.send(binaryInterest);
};

NDN.prototype.registerPrefix = function(name, closure, flag) {
    var thisNDN = this;
    var onConnected = function() {
    	if (thisNDN.ccndid == null) {
            // Fetch ccndid first, then register.
            var interest = new Interest(NDN.ccndIdFetcher);
    		interest.interestLifetime = 4000; // milliseconds
            if (LOG>3) console.log('Expressing interest for ccndid from ccnd.');
            thisNDN.reconnectAndExpressInterest
               (interest, new NDN.FetchCcndidClosure(thisNDN, name, closure, flag));
        }
        else	
            thisNDN.registerPrefixHelper(name, closure, flag);
    };

	if (this.host == null || this.port == null) {
        if (this.getHostAndPort == null)
            console.log('ERROR: host OR port NOT SET');
        else
            this.connectAndExecute(onConnected);
    }
    else
        onConnected();
};

/*
 * This is a closure to receive the ContentObject for NDN.ccndIdFetcher and call
 *   registerPrefixHelper(name, callerClosure, flag).
 */
NDN.FetchCcndidClosure = function FetchCcndidClosure(ndn, name, callerClosure, flag) {
    // Inherit from Closure.
    Closure.call(this);
    
    this.ndn = ndn;
    this.name = name;
    this.callerClosure = callerClosure;
    this.flag = flag;
};

NDN.FetchCcndidClosure.prototype.upcall = function(kind, upcallInfo) {
    if (kind == Closure.UPCALL_INTEREST_TIMED_OUT) {
        console.log("Timeout while requesting the ccndid.  Cannot registerPrefix for " +
            this.name.to_uri() + " .");
        return Closure.RESULT_OK;
    }
    if (!(kind == Closure.UPCALL_CONTENT ||
          kind == Closure.UPCALL_CONTENT_UNVERIFIED))
        // The upcall is not for us.
        return Closure.RESULT_ERR;
       
    var co = upcallInfo.contentObject;
    if (!co.signedInfo || !co.signedInfo.publisher 
		|| !co.signedInfo.publisher.publisherPublicKeyDigest)
        console.log
          ("ContentObject doesn't have a publisherPublicKeyDigest. Cannot set ccndid and registerPrefix for "
           + this.name.to_uri() + " .");
    else {
		if (LOG>3) console.log('Got ccndid from ccnd.');
		this.ndn.ccndid = co.signedInfo.publisher.publisherPublicKeyDigest;
		if (LOG>3) console.log(this.ndn.ccndid);
        
        this.ndn.registerPrefixHelper(this.name, this.callerClosure, this.flag);
	}
    
    return Closure.RESULT_OK;
};

/*
 * Do the work of registerPrefix once we know we are connected with a ccndid.
 */
NDN.prototype.registerPrefixHelper = function(name, closure, flag) {
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
	if (LOG > 3) console.log('Send Interest registration packet.');
    	
    var csEntry = new CSEntry(name.getName(), closure);
	NDN.CSTable.push(csEntry);
    
    this.transport.send(encodeToBinaryInterest(interest));
};

/*
 * This is called when an entire binary XML element is received, such as a ContentObject or Interest.
 * Look up in the PITTable and call the closure callback.
 */
NDN.prototype.onReceivedElement = function(element) {
    if (LOG>3) console.log('Complete element received. Length ' + element.length + '. Start decoding.');
	var decoder = new BinaryXMLDecoder(element);
	// Dispatch according to packet type
	if (decoder.peekStartElement(CCNProtocolDTags.Interest)) {  // Interest packet
		if (LOG > 3) console.log('Interest packet received.');
				
		var interest = new Interest();
		interest.from_ccnb(decoder);
		if (LOG > 3) console.log(interest);
		var nameStr = escape(interest.name.getName());
		if (LOG > 3) console.log(nameStr);
				
		var entry = getEntryForRegisteredPrefix(nameStr);
		if (entry != null) {
			//console.log(entry);
			var info = new UpcallInfo(this, interest, 0, null);
			var ret = entry.closure.upcall(Closure.UPCALL_INTEREST, info);
			if (ret == Closure.RESULT_INTEREST_CONSUMED && info.contentObject != null) 
				this.transport.send(encodeToBinaryContentObject(info.contentObject));
		}				
	} else if (decoder.peekStartElement(CCNProtocolDTags.ContentObject)) {  // Content packet
		if (LOG > 3) console.log('ContentObject packet received.');
				
		var co = new ContentObject();
		co.from_ccnb(decoder);
				
		var pitEntry = NDN.getEntryForExpressedInterest(co.name);
		if (pitEntry != null) {
			// Cancel interest timer
			clearTimeout(pitEntry.timerID);
            
			// Remove PIT entry from NDN.PITTable
			var index = NDN.PITTable.indexOf(pitEntry);
			if (index >= 0)
				NDN.PITTable.splice(index, 1);
						
			var currentClosure = pitEntry.closure;
										
			if (this.verify == false) {
				// Pass content up without verifying the signature
				currentClosure.upcall(Closure.UPCALL_CONTENT_UNVERIFIED, new UpcallInfo(this, pitEntry.interest, 0, co));
				return;
			}
				
			// Key verification
						
			// Recursive key fetching & verification closure
			var KeyFetchClosure = function KeyFetchClosure(content, closure, key, sig, wit) {
				this.contentObject = content;  // unverified content object
				this.closure = closure;  // closure corresponding to the contentObject
				this.keyName = key;  // name of current key to be fetched
				this.sigHex = sig;  // hex signature string to be verified
				this.witness = wit;
						
				Closure.call(this);
			};
						
            var thisNDN = this;
			KeyFetchClosure.prototype.upcall = function(kind, upcallInfo) {
				if (kind == Closure.UPCALL_INTEREST_TIMED_OUT) {
					console.log("In KeyFetchClosure.upcall: interest time out.");
					console.log(this.keyName.contentName.getName());
				} else if (kind == Closure.UPCALL_CONTENT) {
					//console.log("In KeyFetchClosure.upcall: signature verification passed");
								
					var rsakey = decodeSubjectPublicKeyInfo(upcallInfo.contentObject.content);
					var verified = rsakey.verifyByteArray(this.contentObject.rawSignatureData, this.witness, this.sigHex);
								
					var flag = (verified == true) ? Closure.UPCALL_CONTENT : Closure.UPCALL_CONTENT_BAD;
					//console.log("raise encapsulated closure");
					this.closure.upcall(flag, new UpcallInfo(thisNDN, null, 0, this.contentObject));
								
					// Store key in cache
					var keyEntry = new KeyStoreEntry(keylocator.keyName, rsakey, new Date().getTime());
					NDN.addKeyEntry(keyEntry);
					//console.log(NDN.KeyStore);
				} else if (kind == Closure.UPCALL_CONTENT_BAD) {
					console.log("In KeyFetchClosure.upcall: signature verification failed");
				}
			};
						
			if (co.signedInfo && co.signedInfo.locator && co.signature) {
				if (LOG > 3) console.log("Key verification...");
				var sigHex = DataUtils.toHex(co.signature.signature).toLowerCase();
							
				var wit = null;
				if (co.signature.Witness != null) {
					wit = new Witness();
					wit.decode(co.signature.Witness);
				}
							
				var keylocator = co.signedInfo.locator;
				if (keylocator.type == KeyLocatorType.KEYNAME) {
					if (LOG > 3) console.log("KeyLocator contains KEYNAME");
					//var keyname = keylocator.keyName.contentName.getName();
					//console.log(nameStr);
					//console.log(keyname);
								
					if (keylocator.keyName.contentName.match(co.name)) {
						if (LOG > 3) console.log("Content is key itself");
									
						var rsakey = decodeSubjectPublicKeyInfo(co.content);
						var verified = rsakey.verifyByteArray(co.rawSignatureData, wit, sigHex);
						var flag = (verified == true) ? Closure.UPCALL_CONTENT : Closure.UPCALL_CONTENT_BAD;

						currentClosure.upcall(flag, new UpcallInfo(this, pitEntry.interest, 0, co));

						// SWT: We don't need to store key here since the same key will be
						//      stored again in the closure.
						//var keyEntry = new KeyStoreEntry(keylocator.keyName, rsakey, new Date().getTime());
						//NDN.addKeyEntry(keyEntry);
						//console.log(NDN.KeyStore);
					} else {
						// Check local key store
						var keyEntry = NDN.getKeyByName(keylocator.keyName);
						if (keyEntry) {
							// Key found, verify now
							if (LOG > 3) console.log("Local key cache hit");
							var rsakey = keyEntry.rsaKey;
							var verified = rsakey.verifyByteArray(co.rawSignatureData, wit, sigHex);
							var flag = (verified == true) ? Closure.UPCALL_CONTENT : Closure.UPCALL_CONTENT_BAD;

							// Raise callback
							currentClosure.upcall(flag, new UpcallInfo(this, pitEntry.interest, 0, co));
						} else {
							// Not found, fetch now
							if (LOG > 3) console.log("Fetch key according to keylocator");
							var nextClosure = new KeyFetchClosure(co, currentClosure, keylocator.keyName, sigHex, wit);
							this.expressInterest(keylocator.keyName.contentName.getPrefix(4), nextClosure);
						}
					}
				} else if (keylocator.type == KeyLocatorType.KEY) {
					if (LOG > 3) console.log("Keylocator contains KEY");
								
					var rsakey = decodeSubjectPublicKeyInfo(co.signedInfo.locator.publicKey);
					var verified = rsakey.verifyByteArray(co.rawSignatureData, wit, sigHex);
							
					var flag = (verified == true) ? Closure.UPCALL_CONTENT : Closure.UPCALL_CONTENT_BAD;
					// Raise callback
					currentClosure.upcall(Closure.UPCALL_CONTENT, new UpcallInfo(this, pitEntry.interest, 0, co));

					// Since KeyLocator does not contain key name for this key,
					// we have no way to store it as a key entry in KeyStore.
				} else {
					var cert = keylocator.certificate;
					console.log("KeyLocator contains CERT");
					console.log(cert);
								
					// TODO: verify certificate
				}
			}
		}
	} else
		console.log('Incoming packet is not Interest or ContentObject. Discard now.');
};

/*
 * Assume this.getHostAndPort is not null.  This is called when this.host is null or its host
 *   is not alive.  Get a host and port, connect, then execute onConnected().
 */
NDN.prototype.connectAndExecute = function(onConnected) {
    var hostAndPort = this.getHostAndPort();
    if (hostAndPort == null) {
        console.log('ERROR: No more hosts from getHostAndPort');
        this.host = null;
        return;
    }

    if (hostAndPort.host == this.host && hostAndPort.port == this.port) {
        console.log('ERROR: The host returned by getHostAndPort is not alive: ' + 
                this.host + ":" + this.port);
        return;
    }
        
    this.host = hostAndPort.host;
    this.port = hostAndPort.port;   
    if (LOG>0) console.log("connectAndExecute: trying host from getHostAndPort: " + this.host);
    
    // Fetch any content.
    var interest = new Interest(new Name("/"));
	interest.interestLifetime = 4000; // milliseconds    

    var thisNDN = this;
	var timerID = setTimeout(function() {
        if (LOG>0) console.log("connectAndExecute: timeout waiting for host " + thisNDN.host);
        // Try again.
        thisNDN.connectAndExecute(onConnected);
	}, 3000);
  
    this.reconnectAndExpressInterest
        (interest, new NDN.ConnectClosure(this, onConnected, timerID));
};

NDN.ConnectClosure = function ConnectClosure(ndn, onConnected, timerID) {
    // Inherit from Closure.
    Closure.call(this);
    
    this.ndn = ndn;
    this.onConnected = onConnected;
    this.timerID = timerID;
};

NDN.ConnectClosure.prototype.upcall = function(kind, upcallInfo) {
    if (!(kind == Closure.UPCALL_CONTENT ||
          kind == Closure.UPCALL_CONTENT_UNVERIFIED))
        // The upcall is not for us.
        return Closure.RESULT_ERR;
        
    // The host is alive, so cancel the timeout and continue with onConnected().
    clearTimeout(this.timerID);

    // Call NDN.onopen after success
	this.ndn.readyStatus = NDN.OPENED;
	this.ndn.onopen();

    if (LOG>0) console.log("connectAndExecute: connected to host " + this.ndn.host);
    this.onConnected();

    return Closure.RESULT_OK;
};

/*
 * A BinaryXmlElementReader lets you call onReceivedData multiple times which uses a
 *   BinaryXMLStructureDecoder to detect the end of a binary XML element and calls
 *   elementListener.onReceivedElement(element) with the element. 
 * This handles the case where a single call to onReceivedData may contain multiple elements.
 */
var BinaryXmlElementReader = function BinaryXmlElementReader(elementListener) {
    this.elementListener = elementListener;
	this.dataParts = [];
    this.structureDecoder = new BinaryXMLStructureDecoder();
};

BinaryXmlElementReader.prototype.onReceivedData = function(/* Uint8Array */ rawData) {
    // Process multiple objects in the data.
    while(true) {
        // Scan the input to check if a whole ccnb object has been read.
        this.structureDecoder.seek(0);
        if (this.structureDecoder.findElementEnd(rawData)) {
            // Got the remainder of an object.  Report to the caller.
            this.dataParts.push(rawData.subarray(0, this.structureDecoder.offset));
            var element = DataUtils.concatArrays(this.dataParts);
            this.dataParts = [];
            try {
                this.elementListener.onReceivedElement(element);
            } catch (ex) {
                console.log("BinaryXmlElementReader: ignoring exception from onReceivedElement: " + ex);
            }
        
            // Need to read a new object.
            rawData = rawData.subarray(this.structureDecoder.offset, rawData.length);
            this.structureDecoder = new BinaryXMLStructureDecoder();
            if (rawData.length == 0)
                // No more data in the packet.
                return;
            
            // else loop back to decode.
        }
        else {
            // Save for a later call to concatArrays so that we only copy data once.
            this.dataParts.push(rawData);
			if (LOG>3) console.log('Incomplete packet received. Length ' + rawData.length + '. Wait for more input.');
            return;
        }
    }    
}