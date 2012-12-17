/**
 * @author: Meki Cherkaoui, Jeff Thompson, Wentao Shang
 * See COPYING for copyright and distribution information.
 * This class represents the top-level object for communicating with an NDN host.
 */

var LOG = 0;

/**
 * settings is an associative array with the following defaults:
 * {
 *   getTransport: function() { return new WebSocketTransport(); }
 *   getHostAndPort: transport.defaultGetHostAndPort,
 *   host: 'localhost', // If null, use getHostAndPort when connecting.
 *   port: 9696,
 *   onopen: function() { if (LOG > 3) console.log("NDN connection established."); }
 *   onclose: function() { if (LOG > 3) console.log("NDN connection closed."); }
 * }
 * 
 * getHostAndPort is a function, on each call it returns a new { host: host, port: port } or
 *   null if there are no more hosts.
 */
var NDN = function NDN(settings) {
    settings = (settings || {});
    var getTransport = (settings.getTransport || function() { return new WebSocketTransport(); });
    this.transport = getTransport();
    this.getHostAndPort = (settings.getHostAndPort || this.transport.defaultGetHostAndPort);
	this.host = (settings.host !== undefined ? settings.host : 'localhost');
	this.port = (settings.port || 9696);
    this.readyStatus = NDN.UNOPEN;
    // Event handler
    this.onopen = (settings.onopen || function() { if (LOG > 3) console.log("NDN connection established."); });
    this.onclose = (settings.onclose || function() { if (LOG > 3) console.log("NDN connection closed."); });
};

NDN.UNOPEN = 0;  // created but not opened yet
NDN.OPENED = 1;  // connection to ccnd opened
NDN.CLOSED = 2;  // connection to ccnd closed

NDN.ccndIdFetcher = '/%C1.M.S.localhost/%C1.M.SRV/ccnd/KEY';

NDN.prototype.createRoute = function(host,port){
	this.host=host;
	this.port=port;
}

// For fetching data
NDN.PITTable = new Array();

var PITEntry = function PITEntry(interest, closure) {
	this.interest = interest;  // Interest
	this.closure = closure;    // Closure
};

// Return the longest entry from NDN.PITTable that matches name.
NDN.getEntryForExpressedInterest = function(/*Name*/ name) {
    // TODO: handle multiple matches?  Maybe not from registerPrefix because multiple ContentObject
    //   could be sent for one Interest?
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
        interest.interestLifetime = 4.0;   // default interest timeout value in seconds.

	if (this.host == null || this.port == null) {
        if (this.getHostAndPort == null)
            console.log('ERROR: host OR port NOT SET');
        else
            this.connectAndExpressInterest(interest, closure);
    }
    else
        this.transport.expressInterest(this, interest, closure);
};

NDN.prototype.registerPrefix = function(name, closure, flag) {
    return this.transport.registerPrefix(this, name, closure, flag);
}

/*
 * Assume this.getHostAndPort is not null.  This is called when this.host is null or its host
 *   is not alive.  Get a host and port, connect, then express callerInterest with callerClosure.
 */
NDN.prototype.connectAndExpressInterest = function(callerInterest, callerClosure) {
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
    console.log("Trying host from getHostAndPort: " + this.host);
    
    // Fetch the ccndId.
    var interest = new Interest(new Name(NDN.ccndIdFetcher));
	interest.interestLifetime = 4.0; // seconds    

    var thisNDN = this;
	var timerID = setTimeout(function() {
        console.log("Timeout waiting for host " + thisNDN.host);
        // Try again.
        thisNDN.connectAndExpressInterest(callerInterest, callerClosure);
	}, 3000);
  
    this.transport.expressInterest
        (this, interest, new NDN.ConnectClosure(this, callerInterest, callerClosure, timerID));
}

NDN.ConnectClosure = function ConnectClosure(ndn, callerInterest, callerClosure, timerID) {
    // Inherit from Closure.
    Closure.call(this);
    
    this.ndn = ndn;
    this.callerInterest = callerInterest;
    this.callerClosure = callerClosure;
    this.timerID = timerID;
};

NDN.ConnectClosure.prototype.upcall = function(kind, upcallInfo) {
    if (!(kind == Closure.UPCALL_CONTENT ||
          kind == Closure.UPCALL_CONTENT_UNVERIFIED ||
          kind == Closure.UPCALL_INTEREST))
        // The upcall is not for us.
        return Closure.RESULT_ERR;
        
    // The host is alive, so cancel the timeout and issue the caller's interest.
    clearTimeout(this.timerID);
    console.log(this.ndn.host + ": Host is alive. Fetching callerInterest.");
    this.ndn.transport.expressInterest(this.ndn, this.callerInterest, this.callerClosure);

    return Closure.RESULT_OK;
};

