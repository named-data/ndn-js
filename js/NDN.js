/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Meki Cherkaoui, Jeff Thompson <jefft0@remap.ucla.edu>, Wentao Shang
 * See COPYING for copyright and distribution information.
 * This class represents the top-level object for communicating with an NDN host.
 */

var DataUtils = require('./encoding/data-utils.js').DataUtils;
var Name = require('./name.js').Name;
var Interest = require('./interest.js').Interest;
var ContentObject = require('./content-object.js').ContentObject;
var ForwardingEntry = require('./forwarding-entry.js').ForwardingEntry;
var BinaryXMLDecoder = require('./encoding/binary-xml-decoder.js').BinaryXMLDecoder;
var NDNProtocolDTags = require('./util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var Key = require('./key.js').Key;
var KeyLocatorType = require('./key.js').KeyLocatorType;
var Closure = require('./closure.js').Closure;
var UpcallInfo = require('./closure.js').UpcallInfo;
var TcpTransport = require('./transport/tcp-transport.js').TcpTransport;
var LOG = require('./log.js').Log.LOG;

/**
 * Create a new NDN with the given settings.
 * This throws an exception if NDN.supported is false.
 * @constructor
 * @param {Object} settings if not null, an associative array with the following defaults:
 * {
 *   getTransport: function() { return new WebSocketTransport(); }, // If in the browser.
 *              OR function() { return new TcpTransport(); },       // If in Node.js.
 *   getHostAndPort: transport.defaultGetHostAndPort, // a function, on each call it returns a new { host: host, port: port } or null if there are no more hosts.
 *   host: null, // If null, use getHostAndPort when connecting.
 *   port: 9696, // If in the browser.
 *      OR 6363, // If in Node.js.
 *   onopen: function() { if (LOG > 3) console.log("NDN connection established."); },
 *   onclose: function() { if (LOG > 3) console.log("NDN connection closed."); },
 *   verify: false // If false, don't verify and call upcall with Closure.UPCALL_CONTENT_UNVERIFIED.
 * }
 */
var NDN = function NDN(settings) {
  if (!NDN.supported)
    throw new Error("The necessary JavaScript support is not available on this platform.");
    
  settings = (settings || {});
  // For the browser, browserify-tcp-transport.js replaces TcpTransport with WebSocketTransport.
  var getTransport = (settings.getTransport || function() { return new TcpTransport(); });
  this.transport = getTransport();
  this.getHostAndPort = (settings.getHostAndPort || this.transport.defaultGetHostAndPort);
	this.host = (settings.host !== undefined ? settings.host : null);
	this.port = (settings.port || (typeof WebSocketTransport != 'undefined' ? 9696 : 6363));
  this.readyStatus = NDN.UNOPEN;
  this.verify = (settings.verify !== undefined ? settings.verify : false);
  // Event handler
  this.onopen = (settings.onopen || function() { if (LOG > 3) console.log("NDN connection established."); });
  this.onclose = (settings.onclose || function() { if (LOG > 3) console.log("NDN connection closed."); });
	this.ndndid = null;
};

exports.NDN = NDN;

NDN.UNOPEN = 0;  // created but not opened yet
NDN.OPENED = 1;  // connection to ndnd opened
NDN.CLOSED = 2;  // connection to ndnd closed

/**
 * Return true if necessary JavaScript support is available, else log an error and return false.
 */
NDN.getSupported = function() {
    try {
        var dummy = new Buffer(1).slice(0, 1);
    } catch (ex) {
        console.log("NDN not available: Buffer not supported. " + ex);
        return false;
    }
    
    return true;
};

NDN.supported = NDN.getSupported();

NDN.ndndIdFetcher = new Name('/%C1.M.S.localhost/%C1.M.SRV/ndnd/KEY');

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

NDN.prototype.close = function () {
  if (this.readyStatus != NDN.OPENED)
  	throw new Error('Cannot close because NDN connection is not opened.');

  this.readyStatus = NDN.CLOSED;
  this.transport.close();
};

// For fetching data
NDN.PITTable = new Array();

/**
 * @constructor
 */
var PITEntry = function PITEntry(interest, closure) {
	this.interest = interest;  // Interest
	this.closure = closure;    // Closure
	this.timerID = -1;  // Timer ID
};

/**
 * Return the entry from NDN.PITTable where the name conforms to the interest selectors, and
 * the interest name is the longest that matches name.
 */
NDN.getEntryForExpressedInterest = function(/*Name*/ name) {
    var result = null;
    
	for (var i = 0; i < NDN.PITTable.length; i++) {
		if (NDN.PITTable[i].interest.matchesName(name)) {
            if (result == null || 
                NDN.PITTable[i].interest.name.components.length > result.interest.name.components.length)
                result = NDN.PITTable[i];
        }
	}
    
	return result;
};

// For publishing data
NDN.CSTable = new Array();

/**
 * @constructor
 */
var CSEntry = function CSEntry(name, closure) {
	this.name = name;        // String
	this.closure = closure;  // Closure
};

function getEntryForRegisteredPrefix(name) {
	for (var i = 0; i < NDN.CSTable.length; i++) {
		if (NDN.CSTable[i].name.match(name))
			return NDN.CSTable[i];
	}
	return null;
}

/**
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

/**
 * Encode name as an Interest and send the it to host:port, read the entire response and call
 *  closure.upcall(Closure.UPCALL_CONTENT (or Closure.UPCALL_CONTENT_UNVERIFIED),
 *                 new UpcallInfo(this, interest, 0, contentObject)). 
 * @param {Name} name
 * @param {Closure} closure
 * @param {Interest} template if not null, use its attributes
 */
NDN.prototype.expressInterest = function (name, closure, template) {
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

/**
 * If the host and port are different than the ones in this.transport, then call
 *   this.transport.connect to change the connection (or connect for the first time).
 * Then call expressInterestHelper.
 */
NDN.prototype.reconnectAndExpressInterest = function(interest, closure) {
    if (this.transport.connectedHost != this.host || this.transport.connectedPort != this.port) {
        var thisNDN = this;
        this.transport.connect(thisNDN, function() { thisNDN.expressInterestHelper(interest, closure); });
        this.readyStatus = NDN.OPENED;
    }
    else
        this.expressInterestHelper(interest, closure);
};

/**
 * Do the work of reconnectAndExpressInterest once we know we are connected.  Set the PITTable and call
 *   this.transport.send to send the interest.
 */
NDN.prototype.expressInterestHelper = function(interest, closure) {
    var binaryInterest = interest.encode();
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
			if (LOG > 1) console.log("Interest time out: " + interest.name.toUri());
				
			// Remove PIT entry from NDN.PITTable, even if we add it again later to re-express
            //   the interest because we don't want to match it in the mean time.
            // TODO: Make this a thread-safe operation on the global PITTable.
			var index = NDN.PITTable.indexOf(pitEntry);
			if (index >= 0) 
	            NDN.PITTable.splice(index, 1);
				
			// Raise closure callback
			if (closure.upcall(Closure.UPCALL_INTEREST_TIMED_OUT, 
                  new UpcallInfo(thisNDN, interest, 0, null)) == Closure.RESULT_REEXPRESS) {
			    if (LOG > 1) console.log("Re-express interest: " + interest.name.toUri());
                pitEntry.timerID = setTimeout(timeoutCallback, timeoutMilliseconds);
                NDN.PITTable.push(pitEntry);
                thisNDN.transport.send(binaryInterest);
            }
		};
		pitEntry.timerID = setTimeout(timeoutCallback, timeoutMilliseconds);
	}

	this.transport.send(binaryInterest);
};

/**
 * Register name with the connected NDN hub and receive interests with closure.upcall.
 * @param {Name} name
 * @param {Closure} closure
 * @param {number} flags
 */
NDN.prototype.registerPrefix = function(name, closure, flags) {
    flags = flags | 3;
    var thisNDN = this;
    var onConnected = function() {
    	if (thisNDN.ndndid == null) {
            // Fetch ndndid first, then register.
            var interest = new Interest(NDN.ndndIdFetcher);
    		interest.interestLifetime = 4000; // milliseconds
            if (LOG>3) console.log('Expressing interest for ndndid from ndnd.');
            thisNDN.reconnectAndExpressInterest
               (interest, new NDN.FetchNdndidClosure(thisNDN, name, closure, flags));
        }
        else	
            thisNDN.registerPrefixHelper(name, closure, flags);
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

/**
 * This is a closure to receive the ContentObject for NDN.ndndIdFetcher and call
 *   registerPrefixHelper(name, callerClosure, flags).
 */
NDN.FetchNdndidClosure = function FetchNdndidClosure(ndn, name, callerClosure, flags) {
    // Inherit from Closure.
    Closure.call(this);
    
    this.ndn = ndn;
    this.name = name;
    this.callerClosure = callerClosure;
    this.flags = flags;
};

NDN.FetchNdndidClosure.prototype.upcall = function(kind, upcallInfo) {
    if (kind == Closure.UPCALL_INTEREST_TIMED_OUT) {
        console.log("Timeout while requesting the ndndid.  Cannot registerPrefix for " +
            this.name.toUri() + " .");
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
          ("ContentObject doesn't have a publisherPublicKeyDigest. Cannot set ndndid and registerPrefix for "
           + this.name.toUri() + " .");
    else {
		if (LOG>3) console.log('Got ndndid from ndnd.');
		this.ndn.ndndid = co.signedInfo.publisher.publisherPublicKeyDigest;
		if (LOG>3) console.log(this.ndn.ndndid);
        
        this.ndn.registerPrefixHelper(this.name, this.callerClosure, this.flags);
	}
    
    return Closure.RESULT_OK;
};

/**
 * Do the work of registerPrefix once we know we are connected with a ndndid.
 */
NDN.prototype.registerPrefixHelper = function(name, closure, flags) {
	var fe = new ForwardingEntry('selfreg', name, null, null, flags, 2147483647);
  	
  var encoder = new BinaryXMLEncoder();
	fe.to_ndnb(encoder);
	var bytes = encoder.getReducedOstream();
		
	var si = new SignedInfo();
	si.setFields();
		
	var co = new ContentObject(new Name(), si, bytes); 
	co.sign();
	var coBinary = co.encode();;
		
	//var nodename = unescape('%00%88%E2%F4%9C%91%16%16%D6%21%8E%A0c%95%A5%A6r%11%E0%A0%82%89%A6%A9%85%AB%D6%E2%065%DB%AF');
	var nodename = this.ndndid;
	var interestName = new Name(['ndnx', nodename, 'selfreg', coBinary]);

	var interest = new Interest(interestName);
	interest.scope = 1;
	if (LOG > 3) console.log('Send Interest registration packet.');
    	
    var csEntry = new CSEntry(name.toUri(), closure);
	NDN.CSTable.push(csEntry);
    
    this.transport.send(interest.encode());
};

/**
 * This is called when an entire binary XML element is received, such as a ContentObject or Interest.
 * Look up in the PITTable and call the closure callback.
 */
NDN.prototype.onReceivedElement = function(element) {
    if (LOG>3) console.log('Complete element received. Length ' + element.length + '. Start decoding.');
	var decoder = new BinaryXMLDecoder(element);
	// Dispatch according to packet type
	if (decoder.peekStartElement(NDNProtocolDTags.Interest)) {  // Interest packet
		if (LOG > 3) console.log('Interest packet received.');
				
		var interest = new Interest();
		interest.from_ndnb(decoder);
		if (LOG > 3) console.log(interest);
		var nameStr = escape(interest.name.toUri());
		if (LOG > 3) console.log(nameStr);
				
		var entry = getEntryForRegisteredPrefix(nameStr);
		if (entry != null) {
			//console.log(entry);
			var info = new UpcallInfo(this, interest, 0, null);
			var ret = entry.closure.upcall(Closure.UPCALL_INTEREST, info);
			if (ret == Closure.RESULT_INTEREST_CONSUMED && info.contentObject != null) 
				this.transport.send(info.contentObject.encode());
		}				
	} else if (decoder.peekStartElement(NDNProtocolDTags.ContentObject)) {  // Content packet
		if (LOG > 3) console.log('ContentObject packet received.');
				
		var co = new ContentObject();
		co.from_ndnb(decoder);
				
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
				//this.sigHex = sig;  // hex signature string to be verified
				//this.witness = wit;
						
				Closure.call(this);
			};
						
		    var thisNDN = this;
			KeyFetchClosure.prototype.upcall = function(kind, upcallInfo) {
				if (kind == Closure.UPCALL_INTEREST_TIMED_OUT) {
					console.log("In KeyFetchClosure.upcall: interest time out.");
					console.log(this.keyName.contentName.toUri());
				} else if (kind == Closure.UPCALL_CONTENT) {
					//console.log("In KeyFetchClosure.upcall: signature verification passed");
								
				    var rsakey = new Key();
				    rsakey.readDerPublicKey(upcallInfo.contentObject.content);
				    var verified = co.verify(rsakey);
								
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
				if (co.signature.witness != null) {
				    //SWT: deprecate support for Witness decoding and Merkle hash tree verification
				    currentClosure.upcall(Closure.UPCALL_CONTENT_BAD, new UpcallInfo(this, pitEntry.interest, 0, co));
				}
			    
				var keylocator = co.signedInfo.locator;
				if (keylocator.type == KeyLocatorType.KEYNAME) {
					if (LOG > 3) console.log("KeyLocator contains KEYNAME");
					//var keyname = keylocator.keyName.contentName.toUri();
					//console.log(nameStr);
					//console.log(keyname);
								
					if (keylocator.keyName.contentName.match(co.name)) {
						if (LOG > 3) console.log("Content is key itself");
									
					    var rsakey = new Key();
					    rsakey.readDerPublicKey(co.content);
					    var verified = co.verify(rsakey);
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
						    var verified = co.verify(rsakey);
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
								
				    var rsakey = new Key();
				    rsakey.readDerPublicKey(keylocator.publicKey);
				    var verified = co.verify(rsakey);
							
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

/**
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

/**
 * This is called by the Transport when the connection is closed by the remote host.
 */
NDN.prototype.closeByTransport = function () {
    this.readyStatus = NDN.CLOSED;
    this.onclose();
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
