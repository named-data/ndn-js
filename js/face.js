/**
 * This class represents the top-level object for communicating with an NDN host.
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Meki Cherkaoui, Jeff Thompson <jefft0@remap.ucla.edu>, Wentao Shang
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var crypto = require('crypto');
var DataUtils = require('./encoding/data-utils.js').DataUtils;
var Name = require('./name.js').Name;
var Interest = require('./interest.js').Interest;
var Data = require('./data.js').Data;
var MetaInfo = require('./meta-info.js').MetaInfo;
var ForwardingEntry = require('./forwarding-entry.js').ForwardingEntry;
var ControlParameters = require('./control-parameters.js').ControlParameters;
var TlvWireFormat = require('./encoding/tlv-wire-format.js').TlvWireFormat;
var BinaryXmlWireFormat = require('./encoding/binary-xml-wire-format.js').BinaryXmlWireFormat;
var Tlv = require('./encoding/tlv/tlv.js').Tlv;
var TlvDecoder = require('./encoding/tlv/tlv-decoder.js').TlvDecoder;
var BinaryXMLDecoder = require('./encoding/binary-xml-decoder.js').BinaryXMLDecoder;
var BinaryXMLEncoder = require('./encoding/binary-xml-encoder.js').BinaryXMLEncoder;
var NDNProtocolDTags = require('./util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var Key = require('./key.js').Key;
var KeyLocatorType = require('./key-locator.js').KeyLocatorType;
var globalKeyManager = require('./security/key-manager.js').globalKeyManager;
var ForwardingFlags = require('./forwarding-flags.js').ForwardingFlags;
var Closure = require('./closure.js').Closure;
var UpcallInfo = require('./closure.js').UpcallInfo;
var Transport = require('./transport/transport.js').Transport;
var TcpTransport = require('./transport/tcp-transport.js').TcpTransport;
var UnixTransport = require('./transport/unix-transport.js').UnixTransport;
var CommandInterestGenerator = require('./util/command-interest-generator.js').CommandInterestGenerator;
var fs = require('fs');
var LOG = require('./log.js').Log.LOG;

/**
 * Create a new Face with the given settings.
 * This throws an exception if Face.supported is false.
 * There are two forms of the constructor.  The first form takes the transport and connectionInfo:
 * Face(transport, connectionInfo).  The second form takes an optional settings object:
 * Face([settings]).
 * @constructor
 * @param {Transport} transport An object of a subclass of Transport to use for
 * communication.
 * @param {Transport.ConnectionInfo} connectionInfo This must be a ConnectionInfo
 * from the same subclass of Transport as transport. If omitted and transport is
 * a new UnixTransport() then attempt to create to the Unix socket for the local
 * forwarder.
 * @param {Object} settings (optional) An associative array with the following defaults:
 * {
 *   getTransport: function() { return new WebSocketTransport(); }, // If in the browser.
 *              OR function() { return new TcpTransport(); },       // If in Node.js.
 *              // If getTransport creates a UnixTransport and connectionInfo is null,
 *              // then connect to the local forwarder's Unix socket.
 *   getConnectionInfo: transport.defaultGetConnectionInfo, // a function, on each call it returns a new Transport.ConnectionInfo or null if there are no more hosts.
 *                                                          // If connectionInfo or host is not null, getConnectionInfo is ignored.
 *   connectionInfo: null,
 *   host: null, // If null and connectionInfo is null, use getConnectionInfo when connecting.
 *               // However, if connectionInfo is not null, use it instead.
 *   port: 9696, // If in the browser.
 *      OR 6363, // If in Node.js.
 *               // However, if connectionInfo is not null, use it instead.
 *   onopen: function() { if (LOG > 3) console.log("NDN connection established."); },
 *   onclose: function() { if (LOG > 3) console.log("NDN connection closed."); },
 *   verify: false // If false, don't verify and call upcall with Closure.UPCALL_CONTENT_UNVERIFIED.
 * }
 */
var Face = function Face(transportOrSettings, connectionInfo)
{
  if (!Face.supported)
    throw new Error("The necessary JavaScript support is not available on this platform.");

  var settings;
  if (typeof transportOrSettings == 'object' && transportOrSettings instanceof Transport) {
    this.getConnectionInfo = null;
    this.transport = transportOrSettings;
    this.connectionInfo = (connectionInfo || null);
    // Use defaults for other settings.
    settings = {};

    if (this.connectionInfo == null) {
      if (this.transport && this.transport.__proto__ &&
          this.transport.__proto__.name == "UnixTransport") {
        // Try to create the default connectionInfo for UnixTransport.
        var filePath = Face.getUnixSocketFilePathForLocalhost();
        if (filePath != null)
          this.connectionInfo = new UnixTransport.ConnectionInfo(filePath);
        else
          console.log
            ("Face constructor: Cannot determine the default Unix socket file path for UnixTransport");
        console.log("Using " + this.connectionInfo.toString());
      }
    }
  }
  else {
    settings = (transportOrSettings || {});
    // For the browser, browserify-tcp-transport.js replaces TcpTransport with WebSocketTransport.
    var getTransport = (settings.getTransport || function() { return new TcpTransport(); });
    this.transport = getTransport();
    this.getConnectionInfo = (settings.getConnectionInfo || this.transport.defaultGetConnectionInfo);

    this.connectionInfo = (settings.connectionInfo || null);
    if (this.connectionInfo == null) {
      var host = (settings.host !== undefined ? settings.host : null);

      if (this.transport && this.transport.__proto__ &&
          this.transport.__proto__.name == "UnixTransport") {
        // We are using UnixTransport on Node.js. There is no IP-style host and port.
        if (host != null)
          // Assume the host is the local Unix socket path.
          this.connectionInfo = new UnixTransport.ConnectionInfo(host);
        else {
          // If getConnectionInfo is not null, it will be used instead so no
          // need to set this.connectionInfo.
          if (this.getConnectionInfo == null) {
            var filePath = Face.getUnixSocketFilePathForLocalhost();
            if (filePath != null)
              this.connectionInfo = new UnixTransport.ConnectionInfo(filePath);
            else
              console.log
                ("Face constructor: Cannot determine the default Unix socket file path for UnixTransport");
          }
        }
      }
      else {
        if (host != null) {
          if (typeof WebSocketTransport != 'undefined')
            this.connectionInfo = new WebSocketTransport.ConnectionInfo
              (host, settings.port || 9696);
          else
            this.connectionInfo = new TcpTransport.ConnectionInfo
              (host, settings.port || 6363);
        }
      }
    }
  }

  // Deprecated: Set this.host and this.port for backwards compatibility.
  if (this.connectionInfo == null) {
    this.host = null;
    this.host = null;
  }
  else {
    this.host = this.connectionInfo.host;
    this.host = this.connectionInfo.port;
  }

  this.readyStatus = Face.UNOPEN;
  this.verify = (settings.verify !== undefined ? settings.verify : false);
  // Event handler
  this.onopen = (settings.onopen || function() { if (LOG > 3) console.log("Face connection established."); });
  this.onclose = (settings.onclose || function() { if (LOG > 3) console.log("Face connection closed."); });
  this.ndndid = null;
  // This is used by reconnectAndExpressInterest.
  this.onConnectedCallbacks = [];
  this.commandKeyChain = null;
  this.commandCertificateName = new Name();
  this.commandInterestGenerator = new CommandInterestGenerator();
};

exports.Face = Face;

Face.UNOPEN = 0;  // the Face is created but not opened yet
Face.OPEN_REQUESTED = 1;  // requested to connect but onopen is not called.
Face.OPENED = 2;  // connection to the forwarder opened
Face.CLOSED = 3;  // connection to the forwarder closed

TcpTransport.importFace(Face);

/**
 * If the forwarder's Unix socket file path exists, then return the file path.
 * Otherwise return an empty string. This uses Node.js blocking file system
 * utilities.
 * @return The Unix socket file path to use, or an empty string.
 */
Face.getUnixSocketFilePathForLocalhost = function()
{
  var filePath = "/var/run/nfd.sock";
  if (fs.existsSync(filePath))
    return filePath;
  else {
    filePath = "/tmp/.ndnd.sock";
    if (fs.existsSync(filePath))
      return filePath;
    else
      return "";
  }
}

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

Face.prototype.createRoute = function(hostOrConnectionInfo, port)
{
  if (hostOrConnectionInfo instanceof Transport.ConnectionInfo)
    this.connectionInfo = hostOrConnectionInfo;
  else
    this.connectionInfo = new TcpTransport.ConnectionInfo(hostOrConnectionInfo, port);

  // Deprecated: Set this.host and this.port for backwards compatibility.
  this.host = this.connectionInfo.host;
  this.host = this.connectionInfo.port;
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
      if (result == null || Face.KeyStore[i].keyName.contentName.size() > result.keyName.contentName.size())
        result = Face.KeyStore[i];
    }
  }

  return result;
};

Face.prototype.close = function()
{
  if (this.readyStatus != Face.OPENED)
    return;

  this.readyStatus = Face.CLOSED;
  this.transport.close();
};

// For fetching data
Face.PITTable = new Array();
Face.PITTableRemoveRequests = new Array();

/**
 * @constructor
 */
var PITEntry = function PITEntry(pendingInterestId, interest, closure)
{
  this.pendingInterestId = pendingInterestId;
  this.interest = interest;  // Interest
  this.closure = closure;    // Closure
  this.timerID = -1;  // Timer ID
};

PITEntry.lastPendingInterestId = 0;

/**
 * Get the next unique pending interest ID.
 *
 * @returns {number} The next pending interest ID.
 */
PITEntry.getNextPendingInterestId = function()
{
  ++PITEntry.lastPendingInterestId;
  return PITEntry.lastPendingInterestId;
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
Face.registeredPrefixRemoveRequests = new Array();

/**
 * @constructor
 */
var RegisteredPrefix = function RegisteredPrefix(registeredPrefixId, prefix, closure)
{
  this.registeredPrefixId = registeredPrefixId;
  this.prefix = prefix;        // String
  this.closure = closure;  // Closure
};

RegisteredPrefix.lastRegisteredPrefixId = 0;

/**
 * Get the next unique registered prefix ID.
 * @returns {number} The next registered prefix ID.
 */
RegisteredPrefix.getNextRegisteredPrefixId = function()
{
  ++RegisteredPrefix.lastRegisteredPrefixId;
  return RegisteredPrefix.lastRegisteredPrefixId;
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
 * Return a function that selects a host at random from hostList and returns
 * makeConnectionInfo(host, port), and if no more hosts remain, return null.
 * @param {Array<string>} hostList An array of host names.
 * @param {number} port The port for the connection.
 * @param {function} makeConnectionInfo This calls makeConnectionInfo(host, port)
 * to make the Transport.ConnectionInfo. For example:
 * function(host, port) { return new TcpTransport.ConnectionInfo(host, port); }
 * @returns {function} A function which returns a Transport.ConnectionInfo.
 */
Face.makeShuffledHostGetConnectionInfo = function(hostList, port, makeConnectionInfo)
{
  // Make a copy.
  hostList = hostList.slice(0, hostList.length);
  DataUtils.shuffle(hostList);

  return function() {
    if (hostList.length == 0)
      return null;

    return makeConnectionInfo(hostList.splice(0, 1)[0], port);
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
 * @param {function} onData When a matching data packet is received, this calls onData(interest, data) where
 * interest is the interest given to expressInterest and data is the received
 * Data object. NOTE: You must not change the interest object - if you need to
 * change it then make a copy.
 * @param {function} onTimeout (optional) If the interest times out according to the interest lifetime,
 *   this calls onTimeout(interest) where:
 *   interest is the interest given to expressInterest.
 * @param {Name} name The Name for the interest. (only used for the second form of expressInterest).
 * @param {Interest} template (optional) If not omitted, copy the interest selectors from this Interest.
 * If omitted, use a default interest lifetime. (only used for the second form of expressInterest).
 * @returns {number} The pending interest ID which can be used with removePendingInterest.
 */
Face.prototype.expressInterest = function(interestOrName, arg2, arg3, arg4)
{
  // There are several overloaded versions of expressInterest, each shown inline below.

  // expressInterest(Name name, Closure closure);                      // deprecated
  // expressInterest(Name name, Closure closure,   Interest template); // deprecated
  if (arg2 && arg2.upcall && typeof arg2.upcall == 'function') {
    // Assume arg2 is the deprecated use with Closure.
    // The first argument is a name. Make the interest from the name and possible template.
    interest = new Interest(interestOrName);
    if (arg3) {
      var template = arg3;
      interest.setMinSuffixComponents(template.getMinSuffixComponents());
      interest.setMaxSuffixComponents(template.getMaxSuffixComponents());
      interest.publisherPublicKeyDigest = template.publisherPublicKeyDigest;
      interest.setExclude(template.getExclude());
      interest.setChildSelector(template.getChildSelector());
      interest.getAnswerOriginKind(template.getAnswerOriginKind());
      interest.setScope(template.getScope());
      interest.setInterestLifetimeMilliseconds(template.getInterestLifetimeMilliseconds());
    }
    else
      interest.setInterestLifetimeMilliseconds(4000);   // default interest timeout value in milliseconds.

    return this.expressInterestWithClosure(interest, arg2);
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
      interest.setMinSuffixComponents(template.getMinSuffixComponents());
      interest.setMaxSuffixComponents(template.getMaxSuffixComponents());
      interest.publisherPublicKeyDigest = template.publisherPublicKeyDigest;
      interest.setExclude(template.getExclude());
      interest.setChildSelector(template.getChildSelector());
      interest.getAnswerOriginKind(template.getAnswerOriginKind());
      interest.setScope(template.getScope());
      interest.setInterestLifetimeMilliseconds(template.getInterestLifetimeMilliseconds());

      onData = arg3;
      onTimeout = (arg4 ? arg4 : function() {});
    }
    // expressInterest(Name name, function onData);
    // expressInterest(Name name, function onData,   function onTimeout);
    else {
      interest.setInterestLifetimeMilliseconds(4000);   // default interest timeout
      onData = arg2;
      onTimeout = (arg3 ? arg3 : function() {});
    }
  }

  // Make a Closure from the callbacks so we can use expressInterestWithClosure.
  // TODO: Convert the PIT to use callbacks, not a closure.
  return this.expressInterestWithClosure(interest, new Face.CallbackClosure(onData, onTimeout));
};

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
 * A private method to send the the interest to host:port, read the entire response and call
 * closure.upcall(Closure.UPCALL_CONTENT (or Closure.UPCALL_CONTENT_UNVERIFIED),
 *                 new UpcallInfo(this, interest, 0, data)).
 * @deprecated Use expressInterest with callback functions, not Closure.
 * @param {Interest} the interest, already processed with a template (if supplied).
 * @param {Closure} closure
 * @returns {number} The pending interest ID which can be used with removePendingInterest.
 */
Face.prototype.expressInterestWithClosure = function(interest, closure)
{
  var pendingInterestId = PITEntry.getNextPendingInterestId();

  if (this.connectionInfo == null) {
    if (this.getConnectionInfo == null)
      console.log('ERROR: connectionInfo is NOT SET');
    else {
      var thisFace = this;
      this.connectAndExecute(function() { 
        thisFace.reconnectAndExpressInterest(pendingInterestId, interest, closure);
      });
    }
  }
  else
    this.reconnectAndExpressInterest(pendingInterestId, interest, closure);

  return pendingInterestId;
};

/**
 * If the host and port are different than the ones in this.transport, then call
 *   this.transport.connect to change the connection (or connect for the first time).
 * Then call expressInterestHelper.
 */
Face.prototype.reconnectAndExpressInterest = function(pendingInterestId, interest, closure)
{
  var thisFace = this;
  if (!this.connectionInfo.equals(this.transport.connectionInfo) || this.readyStatus === Face.UNOPEN) {
    this.readyStatus = Face.OPEN_REQUESTED;
    this.onConnectedCallbacks.push
      (function() { thisFace.expressInterestHelper(pendingInterestId, interest, closure); });

    this.transport.connect
     (this.connectionInfo, this,
      function() {
        thisFace.readyStatus = Face.OPENED;

        // Execute each action requested while the connection was opening.
        while (thisFace.onConnectedCallbacks.length > 0) {
          try {
            thisFace.onConnectedCallbacks.shift()();
          } catch (ex) {
            console.log("Face.reconnectAndExpressInterest: ignoring exception from onConnectedCallbacks: " + ex);
          }
        }

        if (thisFace.onopen)
          // Call Face.onopen after success
          thisFace.onopen();
      },
      function() { thisFace.closeByTransport(); });
  }
  else {
    if (this.readyStatus === Face.OPEN_REQUESTED)
      // The connection is still opening, so add to the interests to express.
      this.onConnectedCallbacks.push
        (function() { thisFace.expressInterestHelper(pendingInterestId, interest, closure); });
    else if (this.readyStatus === Face.OPENED)
      this.expressInterestHelper(pendingInterestId, interest, closure);
    else
      throw new Error
        ("reconnectAndExpressInterest: unexpected connection is not opened");
  }
};

/**
 * Do the work of reconnectAndExpressInterest once we know we are connected.  Set the PITTable and call
 *   this.transport.send to send the interest.
 */
Face.prototype.expressInterestHelper = function(pendingInterestId, interest, closure)
{
  var binaryInterest = interest.wireEncode();
  var thisFace = this;
  //TODO: check local content store first
  if (closure != null) {
    var removeRequestIndex = -1;
    if (removeRequestIndex != null)
      removeRequestIndex = Face.PITTableRemoveRequests.indexOf(pendingInterestId);
    if (removeRequestIndex >= 0)
      // removePendingInterest was called with the pendingInterestId returned by
      //   expressInterest before we got here, so don't add a PIT entry.
      Face.PITTableRemoveRequests.splice(removeRequestIndex, 1);
    else {
      var pitEntry = new PITEntry(pendingInterestId, interest, closure);
      // TODO: This needs to be a single thread-safe transaction on a global object.
      Face.PITTable.push(pitEntry);
      closure.pitEntry = pitEntry;

      // Set interest timer.
      var timeoutMilliseconds = (interest.getInterestLifetimeMilliseconds() || 4000);
      var timeoutCallback = function() {
        if (LOG > 1) console.log("Interest time out: " + interest.getName().toUri());

        // Remove PIT entry from Face.PITTable, even if we add it again later to re-express
        //   the interest because we don't want to match it in the mean time.
        // TODO: Make this a thread-safe operation on the global PITTable.
        var index = Face.PITTable.indexOf(pitEntry);
        if (index >= 0)
          Face.PITTable.splice(index, 1);

        // Raise closure callback
        if (closure.upcall(Closure.UPCALL_INTEREST_TIMED_OUT, new UpcallInfo(thisFace, interest, 0, null)) == Closure.RESULT_REEXPRESS) {
          if (LOG > 1) console.log("Re-express interest: " + interest.getName().toUri());
          pitEntry.timerID = setTimeout(timeoutCallback, timeoutMilliseconds);
          Face.PITTable.push(pitEntry);
          thisFace.transport.send(binaryInterest.buf());
        }
      };

      pitEntry.timerID = setTimeout(timeoutCallback, timeoutMilliseconds);
    }
  }

  this.transport.send(binaryInterest.buf());
};

/**
 * Remove the pending interest entry with the pendingInterestId from the pending
 * interest table. This does not affect another pending interest with a
 * different pendingInterestId, even if it has the same interest name.
 * If there is no entry with the pendingInterestId, do nothing.
 * @param {number} pendingInterestId The ID returned from expressInterest.
 */
Face.prototype.removePendingInterest = function(pendingInterestId)
{
  if (pendingInterestId == null)
    return;
  
  // Go backwards through the list so we can erase entries.
  // Remove all entries even though pendingInterestId should be unique.
  var count = 0;
  for (var i = Face.PITTable.length - 1; i >= 0; --i) {
    var entry = Face.PITTable[i];
    if (entry.pendingInterestId == pendingInterestId) {
      // Cancel the timeout timer.
      clearTimeout(entry.timerID);

      Face.PITTable.splice(i, 1);
      ++count;
    }
  }

  if (count == 0) {
    // The pendingInterestId was not found. Perhaps this has been called before
    //   the callback in expressInterest can add to the PIT. Add this
    //   removal request which will be checked before adding to the PIT.
    if (Face.PITTableRemoveRequests.indexOf(pendingInterestId) < 0)
      // Not already requested, so add the request.
      Face.PITTableRemoveRequests.push(pendingInterestId);
  }
};

/**
 * Set the KeyChain and certificate name used to sign command interests (e.g. 
 * for registerPrefix).
 * @param {KeyChain} keyChain The KeyChain object for signing interests, which 
 * must remain valid for the life of this Face. You must create the KeyChain 
 * object and pass it in. You can create a default KeyChain for your system with 
 * the default KeyChain constructor.
 * @param {Name} certificateName The certificate name for signing interests.
 * This makes a copy of the Name. You can get the default certificate name with
 * keyChain.getDefaultCertificateName() .
 */
Face.prototype.setCommandSigningInfo = function(keyChain, certificateName)
{
  this.commandKeyChain = keyChain;
  this.commandCertificateName = new Name(certificateName);
};

/**
 * Set the certificate name used to sign command interest (e.g. for
 * registerPrefix), using the KeyChain that was set with setCommandSigningInfo.
 * @param {Name} certificateName The certificate name for signing interest. This 
 * makes a copy of the Name.
 */
Face.prototype.setCommandCertificateName = function(certificateName)
{
  this.commandCertificateName = new Name(certificateName);
};

/**
 * Append a timestamp component and a random value component to interest's name. 
 * Then use the keyChain and certificateName from setCommandSigningInfo to sign 
 * the interest. If the interest lifetime is not set, this sets it.
 * @note This method is an experimental feature. See the API docs for more
 * detail at
 * http://named-data.net/doc/ndn-ccl-api/face.html#face-makecommandinterest-method .
 * @param {Interest} interest The interest whose name is appended with
 * components.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the SignatureInfo and to encode the interest name for signing.  If omitted,
 * use WireFormat.getDefaultWireFormat().
 */
Face.prototype.makeCommandInterest = function(interest, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  this.nodeMakeCommandInterest
    (interest, this.commandKeyChain, this.commandCertificateName, wireFormat);
};

/**
 * Append a timestamp component and a random value component to interest's name.
 * Then use the keyChain and certificateName from setCommandSigningInfo to sign
 * the interest. If the interest lifetime is not set, this sets it.
 * @param {Interest} interest The interest whose name is appended with
 * components.
 * @param {KeyChain} keyChain The KeyChain for calling sign.
 * @param {Name} certificateName The certificate name of the key to use for
 * signing.
 * @param {WireFormat} wireFormat A WireFormat object used to encode
 * the SignatureInfo and to encode the interest name for signing.
 */
Face.prototype.nodeMakeCommandInterest = function
  (interest, keyChain, certificateName, wireFormat)
{
  this.commandInterestGenerator.generate
    (interest, keyChain, certificateName, wireFormat);
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
 * NOTE: You must not change the prefix object - if you need to change it then
 * make a copy.
 * @param {function} onRegisterFailed If register prefix fails for any reason,
 * this calls onRegisterFailed(prefix) where:
 *   prefix is the prefix given to registerPrefix.
 * @param {ForwardingFlags} flags (optional) The ForwardingFlags object for finer control of which interests are forward to the application.
 * If omitted, use the default flags defined by the default ForwardingFlags constructor.
 * @param {number} intFlags (optional) (only for the deprecated form of
 * registerPrefix) The integer NDNx flags for finer control of which interests
 * are forward to the application.
 * @returns {number} The registered prefix ID which can be used with
 * removeRegisteredPrefix.
 */
Face.prototype.registerPrefix = function(prefix, arg2, arg3, arg4)
{
  // There are several overloaded versions of registerPrefix, each shown inline below.

  // registerPrefix(Name prefix, Closure closure);            // deprecated
  // registerPrefix(Name prefix, Closure closure, int flags); // deprecated
  if (arg2 && arg2.upcall && typeof arg2.upcall == 'function') {
    // Assume arg2 is the deprecated use with Closure.
    if (arg3) {
      var flags;
      if (typeof flags === 'number') {
        // Assume this deprecated form is only called for NDNx.
        flags = new ForwardingFlags();
        flags.setForwardingEntryFlags(arg3);
      }
      else
        // Assume arg3 is already a ForwardingFlags.
        flags = arg3;
      return this.registerPrefixWithClosure(prefix, arg2, flags);
    }
    else
      return this.registerPrefixWithClosure(prefix, arg2, new ForwardingFlags());
  }

  // registerPrefix(Name prefix, function onInterest, function onRegisterFailed);
  // registerPrefix(Name prefix, function onInterest, function onRegisterFailed, ForwardingFlags flags);
  var onInterest = arg2;
  var onRegisterFailed = (arg3 ? arg3 : function() {});
  var flags = (arg4 ? arg4 : new ForwardingFlags());
  return this.registerPrefixWithClosure
    (prefix, new Face.CallbackClosure(null, null, onInterest, prefix, this.transport),
     flags, onRegisterFailed);
};

/**
 * A private method to register the prefix with the host, receive the data and call
 * closure.upcall(Closure.UPCALL_INTEREST, new UpcallInfo(this, interest, 0, null)).
 * @deprecated Use registerPrefix with callback functions, not Closure.
 * @param {Name} prefix
 * @param {Closure} closure
 * @param {ForwardingFlags} flags
 * @param {function} onRegisterFailed (optional) If called from the
 * non-deprecated registerPrefix, call onRegisterFailed(prefix) if registration
 * fails.
 * @returns {number} The registered prefix ID which can be used with
 * removeRegisteredPrefix.
 */
Face.prototype.registerPrefixWithClosure = function
  (prefix, closure, flags, onRegisterFailed)
{
  var registeredPrefixId = RegisteredPrefix.getNextRegisteredPrefixId();
  var thisFace = this;
  var onConnected = function() {
    // If we have an _ndndId, we know we already connected to NDNx.
    if (thisFace.ndndid != null || thisFace.commandKeyChain == null) {
      // Assume we are connected to a legacy NDNx server.

      if (thisFace.ndndid == null) {
        // Fetch ndndid first, then register.
        var interest = new Interest(Face.ndndIdFetcher);
        interest.setInterestLifetimeMilliseconds(4000);
        if (LOG > 3) console.log('Expressing interest for ndndid from ndnd.');
        thisFace.reconnectAndExpressInterest
          (null, interest, new Face.FetchNdndidClosure
           (thisFace, registeredPrefixId, prefix, closure, flags, onRegisterFailed));
      }
      else
        thisFace.registerPrefixHelper
          (registeredPrefixId, prefix, closure, flags, onRegisterFailed);
    }
    else
      // The application set the KeyChain for signing NFD interests.
      thisFace.nfdRegisterPrefix
        (registeredPrefixId, prefix, closure, flags, onRegisterFailed,
         thisFace.commandKeyChain, thisFace.commandCertificateName);
  };

  if (this.connectionInfo == null) {
    if (this.getConnectionInfo == null)
      console.log('ERROR: connectionInfo is NOT SET');
    else
      this.connectAndExecute(onConnected);
  }
  else
    onConnected();

  return registeredPrefixId;
};

/**
 * This is a closure to receive the Data for Face.ndndIdFetcher and call
 *   registerPrefixHelper(registeredPrefixId, prefix, callerClosure, flags).
 */
Face.FetchNdndidClosure = function FetchNdndidClosure
  (face, registeredPrefixId, prefix, callerClosure, flags, onRegisterFailed)
{
  // Inherit from Closure.
  Closure.call(this);

  this.face = face;
  this.registeredPrefixId = registeredPrefixId;
  this.prefix = prefix;
  this.callerClosure = callerClosure;
  this.flags = flags; // FOrwardingFlags
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
  hash.update(upcallInfo.data.getContent().buf());
  this.face.ndndid = new Buffer(DataUtils.toNumbersIfString(hash.digest()));
  if (LOG > 3) console.log(this.face.ndndid);

  this.face.registerPrefixHelper
    (this.registeredPrefixId, this.prefix, this.callerClosure, this.flags,
     this.onRegisterFailed);

  return Closure.RESULT_OK;
};

/**
 * This is a closure to receive the response Data packet from the register
 * prefix interest sent to the connected NDN hub. If this gets a bad response
 * or a timeout, call onRegisterFailed.
 */
Face.RegisterResponseClosure = function RegisterResponseClosure
  (face, prefix, callerClosure, onRegisterFailed, flags, wireFormat, isNfdCommand)
{
  // Inherit from Closure.
  Closure.call(this);

  this.face = face;
  this.prefix = prefix;
  this.callerClosure = callerClosure;
  this.onRegisterFailed = onRegisterFailed;
  this.flags = flags;
  this.wireFormat = wireFormat;
  this.isNfdCommand = isNfdCommand;
};

Face.RegisterResponseClosure.prototype.upcall = function(kind, upcallInfo)
{
  if (kind == Closure.UPCALL_INTEREST_TIMED_OUT) {
    // We timed out waiting for the response.
    if (this.isNfdCommand) {
      // The application set the commandKeyChain, but we may be connected to NDNx.
      if (this.face.ndndid == null) {
        // Fetch ndndid first, then register.
        // Pass 0 for registeredPrefixId since the entry was already added to
        //   registeredPrefixTable_ on the first try.
        var interest = new Interest(Face.ndndIdFetcher);
        interest.setInterestLifetimeMilliseconds(4000);
        this.face.reconnectAndExpressInterest
          (null, interest, new Face.FetchNdndidClosure
           (this.face, 0, this.prefix, this.closure, this.flags, this.onRegisterFailed));
      }
      else
        // Pass 0 for registeredPrefixId since the entry was already added to
        //   registeredPrefixTable_ on the first try.
        this.face.registerPrefixHelper
          (0, this.prefix, this.closure, this.flags, this.onRegisterFailed);
    }
    else {
      // An NDNx command was sent because there is no commandKeyChain, so we
      //   can't try an NFD command. Or it was sent from this callback after
      //   trying an NFD command. Fail.
      if (this.onRegisterFailed)
        this.onRegisterFailed(this.prefix);
    }
    
    return Closure.RESULT_OK;
  }
  if (!(kind == Closure.UPCALL_CONTENT ||
        kind == Closure.UPCALL_CONTENT_UNVERIFIED))
    // The upcall is not for us.  Don't expect this to happen.
    return Closure.RESULT_ERR;

  if (this.isNfdCommand) {
    // Decode responseData->getContent() and check for a success code.
    // TODO: Move this into the TLV code.
    var statusCode;
    try {
        var decoder = new TlvDecoder(upcallInfo.data.getContent().buf());
        decoder.readNestedTlvsStart(Tlv.NfdCommand_ControlResponse);
        statusCode = decoder.readNonNegativeIntegerTlv(Tlv.NfdCommand_StatusCode);
    }
    catch (e) {
        // Error decoding the ControlResponse.
        if (this.onRegisterFailed)
          this.onRegisterFailed(this.prefix);
        return Closure.RESULT_OK;
    }

    // Status code 200 is "OK".
    if (statusCode != 200) {
      if (this.onRegisterFailed)
        this.onRegisterFailed(this.prefix);
    }

    // Otherwise, silently succeed.
  }
  else {
    var expectedName = new Name("/ndnx/.../selfreg");
    // Got a response. Do a quick check of expected name components.
    if (upcallInfo.data.getName().size() < 4 ||
        !upcallInfo.data.getName().get(0).equals(expectedName.get(0)) ||
        !upcallInfo.data.getName().get(2).equals(expectedName.get(2))) {
      this.onRegisterFailed(this.prefix);
      return Closure.RESULT_OK;
    }

    // Otherwise, silently succeed.
  }

  return Closure.RESULT_OK;
};

/**
 * Do the work of registerPrefix once we know we are connected with an ndndid.
 * @param {type} registeredPrefixId The
 * RegisteredPrefix.getNextRegisteredPrefixId() which registerPrefix got so it
 * could return it to the caller. If this is 0, then don't add to
 * registeredPrefixTable (assuming it has already been done).
 * @param {Name} prefix
 * @param {Closure} closure
 * @param {ForwardingFlags} flags
 * @param {function} onRegisterFailed
 * @returns {undefined}
 */
Face.prototype.registerPrefixHelper = function
  (registeredPrefixId, prefix, closure, flags, onRegisterFailed)
{
  var removeRequestIndex = -1;
  if (removeRequestIndex != null)
    removeRequestIndex = Face.registeredPrefixRemoveRequests.indexOf
      (registeredPrefixId);
  if (removeRequestIndex >= 0) {
    // removeRegisteredPrefix was called with the registeredPrefixId returned by
    //   registerPrefix before we got here, so don't add a registeredPrefixTable
    //   entry.
    Face.registeredPrefixRemoveRequests.splice(removeRequestIndex, 1);
    return;
  }

  // A ForwardingEntry is only used with NDNx.
  var fe = new ForwardingEntry
    ('selfreg', prefix, null, null, flags.getForwardingEntryFlags(), null);

  // Always encode as BinaryXml until we support TLV for ForwardingEntry.
  var encoder = new BinaryXMLEncoder();
  fe.to_ndnb(encoder);
  var bytes = encoder.getReducedOstream();

  var metaInfo = new MetaInfo();
  metaInfo.setFields();
  // Since we encode the register prefix message as BinaryXml, use the full
  //   public key in the key locator to make the legacy NDNx happy.
  metaInfo.locator.setType(KeyLocatorType.KEY);
  metaInfo.locator.setKeyData(globalKeyManager.getKey().publicToDER());

  var data = new Data(new Name(), metaInfo, bytes);
  // Always encode as BinaryXml until we support TLV for ForwardingEntry.
  data.sign(BinaryXmlWireFormat.get());
  var coBinary = data.wireEncode(BinaryXmlWireFormat.get());;

  var nodename = this.ndndid;
  var interestName = new Name(['ndnx', nodename, 'selfreg', coBinary]);

  var interest = new Interest(interestName);
  interest.setInterestLifetimeMilliseconds(4000.0);
  interest.setScope(1);
  if (LOG > 3) console.log('Send Interest registration packet.');

  if (registeredPrefixId != 0)
    Face.registeredPrefixTable.push
      (new RegisteredPrefix(registeredPrefixId, prefix, closure));

  this.reconnectAndExpressInterest
    (null, interest, new Face.RegisterResponseClosure
     (this, prefix, closure, onRegisterFailed, flags, BinaryXmlWireFormat.get(), false));
};

/**
 * Do the work of registerPrefix to register with NFD.
 * @param {number} registeredPrefixId The 
 * RegisteredPrefix.getNextRegisteredPrefixId() which registerPrefix got so it 
 * could return it to the caller. If this is 0, then don't add to 
 * registeredPrefixTable (assuming it has already been done).
 * @param {Name} prefix
 * @param {Closure} closure
 * @param {ForwardingFlags} flags
 * @param {function} onRegisterFailed
 * @param {KeyChain} commandKeyChain
 * @param {Name} commandCertificateName
 */
Face.prototype.nfdRegisterPrefix = function
  (registeredPrefixId, prefix, closure, flags, onRegisterFailed, commandKeyChain,
   commandCertificateName)
{
  var removeRequestIndex = -1;
  if (removeRequestIndex != null)
    removeRequestIndex = Face.registeredPrefixRemoveRequests.indexOf
      (registeredPrefixId);
  if (removeRequestIndex >= 0) {
    // removeRegisteredPrefix was called with the registeredPrefixId returned by
    //   registerPrefix before we got here, so don't add a registeredPrefixTable
    //   entry.
    Face.registeredPrefixRemoveRequests.splice(removeRequestIndex, 1);
    return;
  }

  if (commandKeyChain == null)
      throw new Error
        ("registerPrefix: The command KeyChain has not been set. You must call setCommandSigningInfo.");
  if (commandCertificateName.size() == 0)
      throw new Error
        ("registerPrefix: The command certificate name has not been set. You must call setCommandSigningInfo.");

  var controlParameters = new ControlParameters();
  controlParameters.setName(prefix);

  var commandInterest = new Interest(new Name("/localhost/nfd/rib/register"));
  // NFD only accepts TlvWireFormat packets.
  commandInterest.getName().append
    (controlParameters.wireEncode(TlvWireFormat.get()));
  this.nodeMakeCommandInterest
    (commandInterest, commandKeyChain, commandCertificateName,
     TlvWireFormat.get());
  // The interest is answered by the local host, so set a short timeout.
  commandInterest.setInterestLifetimeMilliseconds(2000.0);

  if (registeredPrefixId != 0)
      // Save the onInterest callback and send the registration interest.
      Face.registeredPrefixTable.push
        (new RegisteredPrefix(registeredPrefixId, prefix, closure));

  this.reconnectAndExpressInterest
    (null, commandInterest, new Face.RegisterResponseClosure
     (this, prefix, closure, onRegisterFailed, flags,
      TlvWireFormat.get(), true));
};

/**
 * Remove the registered prefix entry with the registeredPrefixId from the
 * registered prefix table. This does not affect another registered prefix with
 * a different registeredPrefixId, even if it has the same prefix name. If there
 * is no entry with the registeredPrefixId, do nothing.
 *
 * @param {number} registeredPrefixId The ID returned from registerPrefix.
 */
Face.prototype.removeRegisteredPrefix = function(registeredPrefixId)
{
  // Go backwards through the list so we can erase entries.
  // Remove all entries even though registeredPrefixId should be unique.
  var count = 0;
  for (var i = Face.registeredPrefixTable.length - 1; i >= 0; --i) {
    var entry = Face.registeredPrefixTable[i];
    if (entry.registeredPrefixId == registeredPrefixId) {
      Face.registeredPrefixTable.splice(i, 1);
      ++count;
    }
  }

  if (count == 0) {
    // The registeredPrefixId was not found. Perhaps this has been called before
    //   the callback in registerPrefix can add to the registeredPrefixTable. Add
    //   this removal request which will be checked before adding to the
    //   registeredPrefixTable.
    if (Face.registeredPrefixRemoveRequests.indexOf(registeredPrefixId) < 0)
      // Not already requested, so add the request.
      Face.registeredPrefixRemoveRequests.push(registeredPrefixId);
  }
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

    var entry = getEntryForRegisteredPrefix(interest.getName());
    if (entry != null) {
      if (LOG > 3) console.log("Found registered prefix for " + interest.getName().toUri());
      var info = new UpcallInfo(this, interest, 0, null);
      var ret = entry.closure.upcall(Closure.UPCALL_INTEREST, info);
      if (ret == Closure.RESULT_INTEREST_CONSUMED && info.data != null)
        this.transport.send(info.data.wireEncode().buf());
    }
  }
  else if (data !== null) {
    if (LOG > 3) console.log('Data packet received.');

    var pendingInterests = Face.extractEntriesForExpressedInterest(data.getName());
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

      var thisFace = this;
      KeyFetchClosure.prototype.upcall = function(kind, upcallInfo) {
        if (kind == Closure.UPCALL_INTEREST_TIMED_OUT) {
          console.log("In KeyFetchClosure.upcall: interest time out.");
          console.log(this.keyName.contentName.toUri());
        }
        else if (kind == Closure.UPCALL_CONTENT) {
          var rsakey = new Key();
          rsakey.readDerPublicKey(upcallInfo.data.getContent().buf());
          var verified = data.verify(rsakey);

          var flag = (verified == true) ? Closure.UPCALL_CONTENT : Closure.UPCALL_CONTENT_BAD;
          this.closure.upcall(flag, new UpcallInfo(thisFace, null, 0, this.data));

          // Store key in cache
          var keyEntry = new KeyStoreEntry(keylocator.keyName, rsakey, new Date().getTime());
          Face.addKeyEntry(keyEntry);
        }
        else if (kind == Closure.UPCALL_CONTENT_BAD)
          console.log("In KeyFetchClosure.upcall: signature verification failed");
      };

      if (data.getMetaInfo() && data.getMetaInfo().locator && data.getSignature()) {
        if (LOG > 3) console.log("Key verification...");
        var sigHex = data.getSignature().getSignature().toHex();

        var wit = null;
        if (data.getSignature().witness != null)
            //SWT: deprecate support for Witness decoding and Merkle hash tree verification
            currentClosure.upcall(Closure.UPCALL_CONTENT_BAD, new UpcallInfo(this, pitEntry.interest, 0, data));

        var keylocator = data.getMetaInfo().locator;
        if (keylocator.getType() == KeyLocatorType.KEYNAME) {
          if (LOG > 3) console.log("KeyLocator contains KEYNAME");

          if (keylocator.keyName.contentName.match(data.getName())) {
            if (LOG > 3) console.log("Content is key itself");

            var rsakey = new Key();
            rsakey.readDerPublicKey(data.getContent().buf());
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
        else if (keylocator.getType() == KeyLocatorType.KEY) {
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
 * Assume this.getConnectionInfo is not null.  This is called when
 * this.connectionInfo is null or its host is not alive.
 * Get a connectionInfo, connect, then execute onConnected().
 */
Face.prototype.connectAndExecute = function(onConnected)
{
  var connectionInfo = this.getConnectionInfo();
  if (connectionInfo == null) {
    console.log('ERROR: No more connectionInfo from getConnectionInfo');
    this.connectionInfo = null;
    // Deprecated: Set this.host and this.port for backwards compatibility.
    this.host = null;
    this.host = null;

    return;
  }

  if (connectionInfo.equals(this.connectionInfo)) {
    console.log
      ('ERROR: The host returned by getConnectionInfo is not alive: ' +
       this.connectionInfo.toString());
    return;
  }

  this.connectionInfo = connectionInfo;
  if (LOG>0) console.log("connectAndExecute: trying host from getConnectionInfo: " +
                         this.connectionInfo.toString());
  // Deprecated: Set this.host and this.port for backwards compatibility.
  this.host = this.connectionInfo.host;
  this.host = this.connectionInfo.port;

  // Fetch any content.
  var interest = new Interest(new Name("/"));
  interest.setInterestLifetimeMilliseconds(4000);

  var thisFace = this;
  var timerID = setTimeout(function() {
    if (LOG>0) console.log("connectAndExecute: timeout waiting for host " + thisFace.host);
      // Try again.
      thisFace.connectAndExecute(onConnected);
  }, 3000);

  this.reconnectAndExpressInterest(null, interest, new Face.ConnectClosure(this, onConnected, timerID));
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
NDN.prototype = new Face({ getTransport: function(){}, getConnectionInfo: function(){} });

exports.NDN = NDN;

NDN.supported = Face.supported;
NDN.UNOPEN = Face.UNOPEN;
NDN.OPEN_REQUESTED = Face.OPEN_REQUESTED;
NDN.OPENED = Face.OPENED;
NDN.CLOSED = Face.CLOSED;
