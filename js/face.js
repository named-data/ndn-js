/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Meki Cherkaoui, Jeff Thompson <jefft0@remap.ucla.edu>, Wentao Shang
 * See COPYING for copyright and distribution information.
 * This class represents the top-level object for communicating with an NDN host.
 */

var crypto = require('crypto');
var DataUtils = require('./encoding/data-utils.js').DataUtils;
var Name = require('./name.js').Name;
var Interest = require('./interest.js').Interest;
var Data = require('./data.js').Data;
var MetaInfo = require('./meta-info.js').MetaInfo;
var ForwardingEntry = require('./forwarding-entry.js').ForwardingEntry;
var TlvWireFormat = require('./encoding/tlv-wire-format.js').TlvWireFormat;
var BinaryXmlWireFormat = require('./encoding/binary-xml-wire-format.js').BinaryXmlWireFormat;
var Tlv = require('./encoding/tlv/tlv.js').Tlv;
var TlvDecoder = require('./encoding/tlv/tlv-decoder.js').TlvDecoder;
var BinaryXMLDecoder = require('./encoding/binary-xml-decoder.js').BinaryXMLDecoder;
var BinaryXMLEncoder = require('./encoding/binary-xml-encoder.js').BinaryXMLEncoder;
var NDNProtocolDTags = require('./util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var Key = require('./key.js').Key;
var KeyLocatorType = require('./key-locator.js').KeyLocatorType;
var ForwardingFlags = require('./forwarding-flags.js').ForwardingFlags;
var Closure = require('./closure.js').Closure;
var UpcallInfo = require('./closure.js').UpcallInfo;
var TcpTransport = require('./transport/tcp-transport.js').TcpTransport;
var LOG = require('./log.js').Log.LOG;

/**
 * Create a new Face with the given settings.
 * This throws an exception if Face.supported is false.
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
var Face = function Face(settings) 
{
  if (!Face.supported)
    throw new Error("The necessary JavaScript support is not available on this platform.");
    
  settings = (settings || {});
  // For the browser, browserify-tcp-transport.js replaces TcpTransport with WebSocketTransport.
  var getTransport = (settings.getTransport || function() { return new TcpTransport(); });
  this.transport = getTransport();
  this.getHostAndPort = (settings.getHostAndPort || this.transport.defaultGetHostAndPort);
  this.host = (settings.host !== undefined ? settings.host : null);
  this.port = (settings.port || (typeof WebSocketTransport != 'undefined' ? 9696 : 6363));
  this.readyStatus = Face.UNOPEN;
  this.verify = (settings.verify !== undefined ? settings.verify : false);
  // Event handler
  this.onopen = (settings.onopen || function() { if (LOG > 3) console.log("Face connection established."); });
  this.onclose = (settings.onclose || function() { if (LOG > 3) console.log("Face connection closed."); });
  this.ndndid = null;
};

exports.Face = Face;

Face.UNOPEN = 0;  // created but not opened yet
Face.OPENED = 1;  // connection to ndnd opened
Face.CLOSED = 2;  // connection to ndnd closed

/**
 * Return true if necessary JavaScript support is available, else log an error and return false.
 */
Face.getSupported = function() 
{
  try {
    var dummy = new Buffer(1).slice(0, 1);
  } 
  catch (ex) {
    console.log("NDN not available: Buffer not supported. " + ex);
    return false;
  }
    
  return true;
};

Face.supported = Face.getSupported();

Face.ndndIdFetcher = new Name('/%C1.M.S.localhost/%C1.M.SRV/ndnd/KEY');

Face.prototype.createRoute = function(host, port) 
{
  this.host=host;
  this.port=port;
};

Face.KeyStore = new Array();

var KeyStoreEntry = function KeyStoreEntry(name, rsa, time) 
{
  this.keyName = name;  // KeyName
  this.rsaKey = rsa;    // RSA key
  this.timeStamp = time;  // Time Stamp
};

Face.addKeyEntry = function(/* KeyStoreEntry */ keyEntry) 
{
  var result = Face.getKeyByName(keyEntry.keyName);
  if (result == null) 
    Face.KeyStore.push(keyEntry);
  else
    result = keyEntry;
};

Face.getKeyByName = function(/* KeyName */ name) 
{
  var result = null;
  
  for (var i = 0; i < Face.KeyStore.length; i++) {
    if (Face.KeyStore[i].keyName.contentName.match(name.contentName)) {
      if (result == null || Face.KeyStore[i].keyName.contentName.components.length > result.keyName.contentName.components.length)
        result = Face.KeyStore[i];
    }
  }
    
  return result;
};

Face.prototype.close = function() 
{
  if (this.readyStatus != Face.OPENED)
    throw new Error('Cannot close because Face connection is not opened.');

  this.readyStatus = Face.CLOSED;
  this.transport.close();
};

// For fetching data
Face.PITTable = new Array();

/**
 * @constructor
 */
var PITEntry = function PITEntry(interest, closure) 
{
  this.interest = interest;  // Interest
  this.closure = closure;    // Closure
  this.timerID = -1;  // Timer ID
};

/**
 * Return the entry from Face.PITTable where the name conforms to the interest selectors, and
 * the interest name is the longest that matches name.
 */

/**
 * Find all entries from Face.PITTable where the name conforms to the entry's 
 * interest selectors, remove the entries from the table, cancel their timeout
 * timers and return them.
 * @param {Name} name The name to find the interest for (from the incoming data
 * packet).
 * @returns {Array<PITEntry>} The matching entries from Face.PITTable, or [] if 
 * none are found.
 */
Face.extractEntriesForExpressedInterest = function(name) 
{
  var result = [];
    
  // Go backwards through the list so we can erase entries.
  for (var i = Face.PITTable.length - 1; i >= 0; --i) {
    var entry = Face.PITTable[i];
    if (entry.interest.matchesName(name)) {
      // Cancel the timeout timer.
      clearTimeout(entry.timerID);

      result.push(entry);
      Face.PITTable.splice(i, 1);
    }
  }

  return result;
};

// For publishing data
Face.registeredPrefixTable = new Array();

/**
 * @constructor
 */
var RegisteredPrefix = function RegisteredPrefix(prefix, closure) 
{
  this.prefix = prefix;        // String
  this.closure = closure;  // Closure
};

/**
 * Find the first entry from Face.registeredPrefixTable where the entry prefix is the longest that matches name.
 * @param {Name} name The name to find the PrefixEntry for (from the incoming interest packet).
 * @returns {object} The entry from Face.registeredPrefixTable, or 0 if not found.
 */
function getEntryForRegisteredPrefix(name) 
{
  var iResult = -1;
  
  for (var i = 0; i < Face.registeredPrefixTable.length; i++) {
    if (LOG > 3) console.log("Registered prefix " + i + ": checking if " + Face.registeredPrefixTable[i].prefix + " matches " + name);
    if (Face.registeredPrefixTable[i].prefix.match(name)) {
      if (iResult < 0 || 
          Face.registeredPrefixTable[i].prefix.size() > Face.registeredPrefixTable[iResult].prefix.size())
        // Update to the longer match.
        iResult = i;
    }
  }
  
  if (iResult >= 0)
    return Face.registeredPrefixTable[iResult];
  else
    return null;
}

/**
 * Return a function that selects a host at random from hostList and returns { host: host, port: port }.
 * If no more hosts remain, return null.
 */
Face.makeShuffledGetHostAndPort = function(hostList, port) 
{
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
 * Send the interest through the transport, read the entire response and call onData. 
 * If the interest times out according to interest lifetime, call onTimeout (if not omitted).
 * There are two forms of expressInterest.  The first form takes the exact interest (including lifetime):
 * expressInterest(interest, onData [, onTimeout]).  The second form creates the interest from
 * a name and optional interest template:
 * expressInterest(name [, template], onData [, onTimeout]).
 * This also supports the deprecated form expressInterest(name, closure [, template]), but you should use the other forms.
 * @param {Interest} interest The Interest to send which includes the interest lifetime for the timeout.
 * @param {function} onData When a matching data packet is received, this calls onData(interest, data) where:
 *   interest is the interest given to expressInterest,
 *   data is the received Data object.
 * @param {function} onTimeout (optional) If the interest times out according to the interest lifetime, 
 *   this calls onTimeout(interest) where:
 *   interest is the interest given to expressInterest.
 * @param {Name} name The Name for the interest. (only used for the second form of expressInterest).
 * @param {Interest} template (optional) If not omitted, copy the interest selectors from this Interest. 
 * If omitted, use a default interest lifetime. (only used for the second form of expressInterest).
 */
Face.prototype.expressInterest = function(interestOrName, arg2, arg3, arg4) 
{
  // There are several overloaded versions of expressInterest, each shown inline below.

  // expressInterest(Name name, Closure closure);                      // deprecated
  // expressInterest(Name name, Closure closure,   Interest template); // deprecated
  if (arg2 && arg2.upcall && typeof arg2.upcall == 'function') {
    // Assume arg2 is the deprecated use with Closure.
    if (arg3)
      this.expressInterestWithClosure(interestOrName, arg2, arg3);
    else
      this.expressInterestWithClosure(interestOrName, arg2);
    return;
  }
  
  var interest;
  var onData;
  var onTimeout;
  // expressInterest(Interest interest, function onData);
  // expressInterest(Interest interest, function onData, function onTimeout);
  if (typeof interestOrName == 'object' && interestOrName instanceof Interest) {
    // Just use a copy of the interest.
    interest = new Interest(interestOrName);
    onData = arg2;
    onTimeout = (arg3 ? arg3 : function() {});
  }
  else {
    // The first argument is a name. Make the interest from the name and possible template.
    interest = new Interest(interestOrName);
    // expressInterest(Name name, Interest template, function onData); 
    // expressInterest(Name name, Interest template, function onData, function onTimeout); 
    if (arg2 && typeof arg2 == 'object' && arg2 instanceof Interest) {
      var template = arg2;
      interest.minSuffixComponents = template.minSuffixComponents;
      interest.maxSuffixComponents = template.maxSuffixComponents;
      interest.publisherPublicKeyDigest = template.publisherPublicKeyDigest;
      interest.exclude = template.exclude;
      interest.childSelector = template.childSelector;
      interest.answerOriginKind = template.answerOriginKind;
      interest.scope = template.scope;
      interest.interestLifetime = template.interestLifetime;

      onData = arg3;
      onTimeout = (arg4 ? arg4 : function() {});
    }
    // expressInterest(Name name, function onData); 
    // expressInterest(Name name, function onData,   function onTimeout); 
    else {
      interest.interestLifetime = 4000;   // default interest timeout value in milliseconds.
      onData = arg2;
      onTimeout = (arg3 ? arg3 : function() {});
    }
  }
  
  // Make a Closure from the callbacks so we can use expressInterestWithClosure.
  // TODO: Convert the PIT to use callbacks, not a closure.
  this.expressInterestWithClosure(interest, new Face.CallbackClosure(onData, onTimeout));
}

Face.CallbackClosure = function FaceCallbackClosure(onData, onTimeout, onInterest, prefix, transport) {
  // Inherit from Closure.
  Closure.call(this);
  
  this.onData = onData;
  this.onTimeout = onTimeout;
  this.onInterest = onInterest;
  this.prefix = prefix;
  this.transport = transport;
};

Face.CallbackClosure.prototype.upcall = function(kind, upcallInfo) {
  if (kind == Closure.UPCALL_CONTENT || kind == Closure.UPCALL_CONTENT_UNVERIFIED)
    this.onData(upcallInfo.interest, upcallInfo.data);
  else if (kind == Closure.UPCALL_INTEREST_TIMED_OUT)
    this.onTimeout(upcallInfo.interest);
  else if (kind == Closure.UPCALL_INTEREST)
    // Note: We never return INTEREST_CONSUMED because onInterest will send the result to the transport.
    this.onInterest(this.prefix, upcallInfo.interest, this.transport)
  
  return Closure.RESULT_OK;
};

/**
 * A private method to encode name as an Interest and send the it to host:port, read the entire response and call
 * closure.upcall(Closure.UPCALL_CONTENT (or Closure.UPCALL_CONTENT_UNVERIFIED),
 *                 new UpcallInfo(this, interest, 0, data)). 
 * @deprecated Use expressInterest with callback functions, not Closure.
 * @param {Name} name Encode name as an Interest using the template (if supplied).
 * @param {Closure} closure
 * @param {Interest} template If not null, use its attributes.
 */
Face.prototype.expressInterestWithClosure = function(name, closure, template) 
{
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
      this.connectAndExecute(function() { thisNDN.reconnectAndExpressInterest(interest, closure); });
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
Face.prototype.reconnectAndExpressInterest = function(interest, closure) 
{
  if (this.transport.connectedHost != this.host || this.transport.connectedPort != this.port) {
    var thisNDN = this;
    this.transport.connect(thisNDN, function() { thisNDN.expressInterestHelper(interest, closure); });
    this.readyStatus = Face.OPENED;
  }
  else
    this.expressInterestHelper(interest, closure);
};

/**
 * Do the work of reconnectAndExpressInterest once we know we are connected.  Set the PITTable and call
 *   this.transport.send to send the interest.
 */
Face.prototype.expressInterestHelper = function(interest, closure) 
{
  var binaryInterest = interest.wireEncode();
  var thisNDN = this;    
  //TODO: check local content store first
  if (closure != null) {
    var pitEntry = new PITEntry(interest, closure);
    // TODO: This needs to be a single thread-safe transaction on a global object.
    Face.PITTable.push(pitEntry);
    closure.pitEntry = pitEntry;

    // Set interest timer.
    var timeoutMilliseconds = (interest.interestLifetime || 4000);
    var timeoutCallback = function() {
      if (LOG > 1) console.log("Interest time out: " + interest.name.toUri());
        
      // Remove PIT entry from Face.PITTable, even if we add it again later to re-express
      //   the interest because we don't want to match it in the mean time.
      // TODO: Make this a thread-safe operation on the global PITTable.
      var index = Face.PITTable.indexOf(pitEntry);
      if (index >= 0) 
        Face.PITTable.splice(index, 1);
        
      // Raise closure callback
      if (closure.upcall(Closure.UPCALL_INTEREST_TIMED_OUT, new UpcallInfo(thisNDN, interest, 0, null)) == Closure.RESULT_REEXPRESS) {
        if (LOG > 1) console.log("Re-express interest: " + interest.name.toUri());
        pitEntry.timerID = setTimeout(timeoutCallback, timeoutMilliseconds);
        Face.PITTable.push(pitEntry);
        thisNDN.transport.send(binaryInterest.buf());
      }
    };
  
    pitEntry.timerID = setTimeout(timeoutCallback, timeoutMilliseconds);
  }

  this.transport.send(binaryInterest.buf());
};

/**
 * Register prefix with the connected NDN hub and call onInterest when a matching interest is received.
 * This uses the form:
 * registerPrefix(name, onInterest, onRegisterFailed [, flags]).
 * This also supports the deprecated form registerPrefix(name, closure [, intFlags]), but you should use the main form.
 * @param {Name} prefix The Name prefix.
 * @param {function} onInterest When an interest is received which matches the name prefix, this calls 
 * onInterest(prefix, interest, transport) where:
 *   prefix is the prefix given to registerPrefix.
 *   interest is the received interest.
 *   transport The Transport with the connection which received the interest. You must encode a signed Data packet and send it using transport.send().
 * @param {function} onRegisterFailed If failed to retrieve the connected hub's ID or failed to register the prefix, 
 * this calls onRegisterFailed(prefix) where:
 *   prefix is the prefix given to registerPrefix.
 * @param {ForwardingFlags} flags (optional) The flags for finer control of which interests are forward to the application.  
 * If omitted, use the default flags defined by the default ForwardingFlags constructor.
 */
Face.prototype.registerPrefix = function(prefix, arg2, arg3, arg4) 
{
  // There are several overloaded versions of registerPrefix, each shown inline below.

  // registerPrefix(Name prefix, Closure closure);            // deprecated
  // registerPrefix(Name prefix, Closure closure, int flags); // deprecated
  if (arg2 && arg2.upcall && typeof arg2.upcall == 'function') {
    // Assume arg2 is the deprecated use with Closure.
    if (arg3)
      this.registerPrefixWithClosure(prefix, arg2, arg3);
    else
      this.registerPrefixWithClosure(prefix, arg2);
    return;
  }

  // registerPrefix(Name prefix, function onInterest, function onRegisterFailed);
  // registerPrefix(Name prefix, function onInterest, function onRegisterFailed, ForwardingFlags flags);
  var onInterest = arg2;
  var onRegisterFailed = (arg3 ? arg3 : function() {});
  var intFlags = (arg4 ? arg4.getForwardingEntryFlags() : new ForwardingFlags().getForwardingEntryFlags());
  this.registerPrefixWithClosure(prefix, new Face.CallbackClosure(null, null, onInterest, prefix, this.transport), 
                                 intFlags, onRegisterFailed);
}

/**
 * A private method to register the prefix with the host, receive the data and call
 * closure.upcall(Closure.UPCALL_INTEREST, new UpcallInfo(this, interest, 0, null)). 
 * @deprecated Use registerPrefix with callback functions, not Closure.
 * @param {Name} prefix
 * @param {Closure} closure
 * @param {number} intFlags
 * @param {function} (optional) If called from the non-deprecated registerPrefix, call onRegisterFailed(prefix) 
 * if registration fails.
 */
Face.prototype.registerPrefixWithClosure = function(prefix, closure, intFlags, onRegisterFailed) 
{
  intFlags = intFlags | 3;
  var thisNDN = this;
  var onConnected = function() {
    if (thisNDN.ndndid == null) {
      // Fetch ndndid first, then register.
      var interest = new Interest(Face.ndndIdFetcher);
      interest.interestLifetime = 4000; // milliseconds
      if (LOG > 3) console.log('Expressing interest for ndndid from ndnd.');
      thisNDN.reconnectAndExpressInterest
        (interest, new Face.FetchNdndidClosure(thisNDN, prefix, closure, intFlags, onRegisterFailed));
    }
    else  
      thisNDN.registerPrefixHelper(prefix, closure, flags, onRegisterFailed);
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
 * This is a closure to receive the Data for Face.ndndIdFetcher and call
 *   registerPrefixHelper(prefix, callerClosure, flags).
 */
Face.FetchNdndidClosure = function FetchNdndidClosure(face, prefix, callerClosure, flags, onRegisterFailed) 
{
  // Inherit from Closure.
  Closure.call(this);
    
  this.face = face;
  this.prefix = prefix;
  this.callerClosure = callerClosure;
  this.flags = flags;
  this.onRegisterFailed = onRegisterFailed;
};

Face.FetchNdndidClosure.prototype.upcall = function(kind, upcallInfo) 
{
  if (kind == Closure.UPCALL_INTEREST_TIMED_OUT) {
    console.log("Timeout while requesting the ndndid.  Cannot registerPrefix for " + this.prefix.toUri() + " .");
    if (this.onRegisterFailed)
      this.onRegisterFailed(this.prefix);
    return Closure.RESULT_OK;
  }
  if (!(kind == Closure.UPCALL_CONTENT ||
        kind == Closure.UPCALL_CONTENT_UNVERIFIED))
    // The upcall is not for us.  Don't expect this to happen.
    return Closure.RESULT_ERR;
       
  if (LOG > 3) console.log('Got ndndid from ndnd.');
  // Get the digest of the public key in the data packet content.
  var hash = require("crypto").createHash('sha256');
  hash.update(upcallInfo.data.getContent());
  this.face.ndndid = new Buffer(hash.digest());
  if (LOG > 3) console.log(this.face.ndndid);
  
  this.face.registerPrefixHelper
    (this.prefix, this.callerClosure, this.flags, this.onRegisterFailed);
    
  return Closure.RESULT_OK;
};
/**
 * This is a closure to receive the response Data packet from the register 
 * prefix interest sent to the connected NDN hub. If this gets a bad response
 * or a timeout, call onRegisterFailed.
 */
Face.RegisterResponseClosure = function RegisterResponseClosure
  (prefix, onRegisterFailed) 
{
  // Inherit from Closure.
  Closure.call(this);
    
  this.prefix = prefix;
  this.onRegisterFailed = onRegisterFailed;
};

Face.RegisterResponseClosure.prototype.upcall = function(kind, upcallInfo) 
{
  if (kind == Closure.UPCALL_INTEREST_TIMED_OUT) {
    if (this.onRegisterFailed)
      this.onRegisterFailed(this.prefix);
    return Closure.RESULT_OK;
  }
  if (!(kind == Closure.UPCALL_CONTENT ||
        kind == Closure.UPCALL_CONTENT_UNVERIFIED))
    // The upcall is not for us.  Don't expect this to happen.
    return Closure.RESULT_ERR;
       
  var expectedName = new Name("/ndnx/.../selfreg");
  // Got a response. Do a quick check of expected name components.
  if (upcallInfo.data.getName().size() < 4 ||
      !upcallInfo.data.getName().get(0).equals(expectedName.get(0)) ||
      !upcallInfo.data.getName().get(2).equals(expectedName.get(2))) {
    this.onRegisterFailed(this.prefix);
    return;
  }
  
  // Otherwise, silently succeed.  
  return Closure.RESULT_OK;
};

/**
 * Do the work of registerPrefix once we know we are connected with a ndndid.
 */
Face.prototype.registerPrefixHelper = function
  (prefix, closure, flags, onRegisterFailed) 
{
  var fe = new ForwardingEntry('selfreg', prefix, null, null, flags, null);
    
  // Always encode as BinaryXml until we support TLV for ForwardingEntry.
  var encoder = new BinaryXMLEncoder();
  fe.to_ndnb(encoder);
  var bytes = encoder.getReducedOstream();
    
  var si = new MetaInfo();
  si.setFields();
    
  // Set the name to a random value so that each request is unique.
  var data = new Data(new Name().append(crypto.randomBytes(4)), si, bytes); 
  // Always encode as BinaryXml until we support TLV for ForwardingEntry.
  data.sign(BinaryXmlWireFormat.get());
  var coBinary = data.wireEncode(BinaryXmlWireFormat.get());;
    
  var nodename = this.ndndid;
  var interestName = new Name(['ndnx', nodename, 'selfreg', coBinary]);

  var interest = new Interest(interestName);
  interest.setInterestLifetimeMilliseconds(4000.0);
  interest.setScope(1);
  if (LOG > 3) console.log('Send Interest registration packet.');
      
  Face.registeredPrefixTable.push(new RegisteredPrefix(prefix, closure));
    
  this.reconnectAndExpressInterest
    (interest, new Face.RegisterResponseClosure(prefix, onRegisterFailed));
};

/**
 * This is called when an entire binary XML element is received, such as a Data or Interest.
 * Look up in the PITTable and call the closure callback.
 */
Face.prototype.onReceivedElement = function(element) 
{
  if (LOG > 3) console.log('Complete element received. Length ' + element.length + '. Start decoding.');
  // First, decode as Interest or Data.
  var interest = null;
  var data = null;
  // The type codes for TLV Interest and Data packets are chosen to not
  //   conflict with the first byte of a binary XML packet, so we can
  //   just look at the first byte.
  if (element[0] == Tlv.Interest || element[0] == Tlv.Data) {
    var decoder = new TlvDecoder (element);  
    if (decoder.peekType(Tlv.Interest, element.length)) {
      interest = new Interest();
      interest.wireDecode(element, TlvWireFormat.get());
    }
    else if (decoder.peekType(Tlv.Data, element.length)) {
      data = new Data();
      data.wireDecode(element, TlvWireFormat.get());
    }
  }
  else {
    // Binary XML.
    var decoder = new BinaryXMLDecoder(element);
    if (decoder.peekDTag(NDNProtocolDTags.Interest)) {
      interest = new Interest();
      interest.wireDecode(element, BinaryXmlWireFormat.get());
    }
    else if (decoder.peekDTag(NDNProtocolDTags.Data)) {
      data = new Data();
      data.wireDecode(element, BinaryXmlWireFormat.get());
    }
  }

  // Now process as Interest or Data.
  if (interest !== null) {
    if (LOG > 3) console.log('Interest packet received.');
        
    var entry = getEntryForRegisteredPrefix(interest.name);
    if (entry != null) {
      if (LOG > 3) console.log("Found registered prefix for " + interest.name.toUri());
      var info = new UpcallInfo(this, interest, 0, null);
      var ret = entry.closure.upcall(Closure.UPCALL_INTEREST, info);
      if (ret == Closure.RESULT_INTEREST_CONSUMED && info.data != null) 
        this.transport.send(info.data.wireEncode().buf());
    }        
  } 
  else if (data !== null) {
    if (LOG > 3) console.log('Data packet received.');
        
    var pendingInterests = Face.extractEntriesForExpressedInterest(data.name);
    // Process each matching PIT entry (if any).
    for (var i = 0; i < pendingInterests.length; ++i) {
      var pitEntry = pendingInterests[i];
      var currentClosure = pitEntry.closure;
                    
      if (this.verify == false) {
        // Pass content up without verifying the signature
        currentClosure.upcall(Closure.UPCALL_CONTENT_UNVERIFIED, new UpcallInfo(this, pitEntry.interest, 0, data));
        continue;
      }
        
      // Key verification
            
      // Recursive key fetching & verification closure
      var KeyFetchClosure = function KeyFetchClosure(content, closure, key, sig, wit) {
        this.data = content;  // unverified data packet object
        this.closure = closure;  // closure corresponding to the data
        this.keyName = key;  // name of current key to be fetched
            
        Closure.call(this);
      };
            
      var thisNDN = this;
      KeyFetchClosure.prototype.upcall = function(kind, upcallInfo) {
        if (kind == Closure.UPCALL_INTEREST_TIMED_OUT) {
          console.log("In KeyFetchClosure.upcall: interest time out.");
          console.log(this.keyName.contentName.toUri());
        } 
        else if (kind == Closure.UPCALL_CONTENT) {
          var rsakey = new Key();
          rsakey.readDerPublicKey(upcallInfo.data.content);
          var verified = data.verify(rsakey);
                
          var flag = (verified == true) ? Closure.UPCALL_CONTENT : Closure.UPCALL_CONTENT_BAD;
          this.closure.upcall(flag, new UpcallInfo(thisNDN, null, 0, this.data));
                
          // Store key in cache
          var keyEntry = new KeyStoreEntry(keylocator.keyName, rsakey, new Date().getTime());
          Face.addKeyEntry(keyEntry);
        } 
        else if (kind == Closure.UPCALL_CONTENT_BAD)
          console.log("In KeyFetchClosure.upcall: signature verification failed");
      };
            
      if (data.signedInfo && data.signedInfo.locator && data.signature) {
        if (LOG > 3) console.log("Key verification...");
        var sigHex = DataUtils.toHex(data.signature.signature).toLowerCase();
              
        var wit = null;
        if (data.signature.witness != null)
            //SWT: deprecate support for Witness decoding and Merkle hash tree verification
            currentClosure.upcall(Closure.UPCALL_CONTENT_BAD, new UpcallInfo(this, pitEntry.interest, 0, data));
          
        var keylocator = data.signedInfo.locator;
        if (keylocator.type == KeyLocatorType.KEYNAME) {
          if (LOG > 3) console.log("KeyLocator contains KEYNAME");
                
          if (keylocator.keyName.contentName.match(data.name)) {
            if (LOG > 3) console.log("Content is key itself");
                  
            var rsakey = new Key();
            rsakey.readDerPublicKey(data.content);
            var verified = data.verify(rsakey);
            var flag = (verified == true) ? Closure.UPCALL_CONTENT : Closure.UPCALL_CONTENT_BAD;
              
            currentClosure.upcall(flag, new UpcallInfo(this, pitEntry.interest, 0, data));

            // SWT: We don't need to store key here since the same key will be stored again in the closure.
          } 
          else {
            // Check local key store
            var keyEntry = Face.getKeyByName(keylocator.keyName);
            if (keyEntry) {
              // Key found, verify now
              if (LOG > 3) console.log("Local key cache hit");
              var rsakey = keyEntry.rsaKey;
              var verified = data.verify(rsakey);
              var flag = (verified == true) ? Closure.UPCALL_CONTENT : Closure.UPCALL_CONTENT_BAD;

              // Raise callback
              currentClosure.upcall(flag, new UpcallInfo(this, pitEntry.interest, 0, data));
            } 
            else {
              // Not found, fetch now
              if (LOG > 3) console.log("Fetch key according to keylocator");
              var nextClosure = new KeyFetchClosure(data, currentClosure, keylocator.keyName, sigHex, wit);
              // TODO: Use expressInterest with callbacks, not Closure.
              this.expressInterest(keylocator.keyName.contentName.getPrefix(4), nextClosure);
            }
          }
        } 
        else if (keylocator.type == KeyLocatorType.KEY) {
          if (LOG > 3) console.log("Keylocator contains KEY");
                
          var rsakey = new Key();
          rsakey.readDerPublicKey(keylocator.publicKey);
          var verified = data.verify(rsakey);
              
          var flag = (verified == true) ? Closure.UPCALL_CONTENT : Closure.UPCALL_CONTENT_BAD;
          // Raise callback
          currentClosure.upcall(Closure.UPCALL_CONTENT, new UpcallInfo(this, pitEntry.interest, 0, data));

          // Since KeyLocator does not contain key name for this key,
          // we have no way to store it as a key entry in KeyStore.
        } 
        else {
          var cert = keylocator.certificate;
          console.log("KeyLocator contains CERT");
          console.log(cert);                
          // TODO: verify certificate
        }
      }
    }
  } 
};

/**
 * Assume this.getHostAndPort is not null.  This is called when this.host is null or its host
 *   is not alive.  Get a host and port, connect, then execute onConnected().
 */
Face.prototype.connectAndExecute = function(onConnected) 
{
  var hostAndPort = this.getHostAndPort();
  if (hostAndPort == null) {
    console.log('ERROR: No more hosts from getHostAndPort');
    this.host = null;
    return;
  }

  if (hostAndPort.host == this.host && hostAndPort.port == this.port) {
    console.log('ERROR: The host returned by getHostAndPort is not alive: ' + this.host + ":" + this.port);
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
  
  this.reconnectAndExpressInterest(interest, new Face.ConnectClosure(this, onConnected, timerID));
};

/**
 * This is called by the Transport when the connection is closed by the remote host.
 */
Face.prototype.closeByTransport = function() 
{
  this.readyStatus = Face.CLOSED;
  this.onclose();
};

Face.ConnectClosure = function ConnectClosure(face, onConnected, timerID) 
{
  // Inherit from Closure.
  Closure.call(this);
    
  this.face = face;
  this.onConnected = onConnected;
  this.timerID = timerID;
};

Face.ConnectClosure.prototype.upcall = function(kind, upcallInfo) 
{
  if (!(kind == Closure.UPCALL_CONTENT ||
        kind == Closure.UPCALL_CONTENT_UNVERIFIED))
    // The upcall is not for us.
    return Closure.RESULT_ERR;
        
  // The host is alive, so cancel the timeout and continue with onConnected().
  clearTimeout(this.timerID);

    // Call Face.onopen after success
  this.face.readyStatus = Face.OPENED;
  this.face.onopen();

  if (LOG>0) console.log("connectAndExecute: connected to host " + this.face.host);
  this.onConnected();

  return Closure.RESULT_OK;
};

/**
 * @deprecated Use new Face.
 */
var NDN = function NDN(settings) 
{
  // Call the base constructor.
  Face.call(this, settings); 
}

// Use dummy functions so that the Face constructor will not try to set its own defaults.                                      
NDN.prototype = new Face({ getTransport: function(){}, getHostAndPort: function(){} });

exports.NDN = NDN;

NDN.supported = Face.supported;
NDN.UNOPEN = Face.UNOPEN;
NDN.OPENED = Face.OPENED;
NDN.CLOSED = Face.CLOSED;
