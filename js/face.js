/**
 * This class represents the top-level object for communicating with an NDN host.
 * Copyright (C) 2013-2018 Regents of the University of California.
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
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU Lesser General Public License is in the file COPYING.
 */

/** @ignore */
var DataUtils = require('./encoding/data-utils.js').DataUtils; /** @ignore */
var Name = require('./name.js').Name; /** @ignore */
var Interest = require('./interest.js').Interest; /** @ignore */
var Data = require('./data.js').Data; /** @ignore */
var ControlParameters = require('./control-parameters.js').ControlParameters; /** @ignore */
var ControlResponse = require('./control-response.js').ControlResponse; /** @ignore */
var InterestFilter = require('./interest-filter.js').InterestFilter; /** @ignore */
var WireFormat = require('./encoding/wire-format.js').WireFormat; /** @ignore */
var TlvWireFormat = require('./encoding/tlv-wire-format.js').TlvWireFormat; /** @ignore */
var Tlv = require('./encoding/tlv/tlv.js').Tlv; /** @ignore */
var TlvDecoder = require('./encoding/tlv/tlv-decoder.js').TlvDecoder; /** @ignore */
var ForwardingFlags = require('./forwarding-flags.js').ForwardingFlags; /** @ignore */
var Transport = require('./transport/transport.js').Transport; /** @ignore */
var TcpTransport = require('./transport/tcp-transport.js').TcpTransport; /** @ignore */
var UnixTransport = require('./transport/unix-transport.js').UnixTransport; /** @ignore */
var CommandInterestGenerator = require('./util/command-interest-generator.js').CommandInterestGenerator; /** @ignore */
var Blob = require('./util/blob.js').Blob; /** @ignore */
var NdnCommon = require('./util/ndn-common.js').NdnCommon; /** @ignore */
var NetworkNack = require('./network-nack.js').NetworkNack; /** @ignore */
var LpPacket = require('./lp/lp-packet.js').LpPacket; /** @ignore */
var InterestFilterTable = require('./impl/interest-filter-table.js').InterestFilterTable; /** @ignore */
var PendingInterestTable = require('./impl/pending-interest-table.js').PendingInterestTable; /** @ignore */
var RegisteredPrefixTable = require('./impl/registered-prefix-table.js').RegisteredPrefixTable; /** @ignore */
var fs = require('fs'); /** @ignore */
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
        if (LOG > 0)
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

  // Event handler
  this.onopen = (settings.onopen || function() { if (LOG > 3) console.log("Face connection established."); });
  this.onclose = (settings.onclose || function() { if (LOG > 3) console.log("Face connection closed."); });
  // This is used by reconnectAndExpressInterest.
  this.onConnectedCallbacks = [];
  this.commandKeyChain = null;
  this.commandCertificateName = new Name();
  this.commandInterestGenerator = new CommandInterestGenerator();
  this.timeoutPrefix = new Name("/local/timeout");

  this.pendingInterestTable_ = new PendingInterestTable();
  this.interestFilterTable_ = new InterestFilterTable();
  this.registeredPrefixTable_ = new RegisteredPrefixTable(this.interestFilterTable_);
  this.lastEntryId = 0;
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

Face.prototype.close = function()
{
  if (this.readyStatus != Face.OPENED)
    return;

  this.readyStatus = Face.CLOSED;
  this.transport.close();
};

/**
 * An internal method to get the next unique entry ID for the pending interest
 * table, interest filter table, etc. Most entry IDs are for the pending
 * interest table (there usually are not many interest filter table entries) so
 * we use a common pool to only have to have one method which is called by Face.
 *
 * @return {number} The next entry ID.
 */
Face.prototype.getNextEntryId = function()
{
  return ++this.lastEntryId;
};

/**
 * Return a function that selects a host at random from hostList and returns
 * makeConnectionInfo(host, port), and if no more hosts remain, return null.
 * @param {Array<string>} hostList An array of host names.
 * @param {number} port The port for the connection.
 * @param {function} makeConnectionInfo This calls makeConnectionInfo(host, port)
 * to make the Transport.ConnectionInfo. For example:
 * function(host, port) { return new TcpTransport.ConnectionInfo(host, port); }
 * @return {function} A function which returns a Transport.ConnectionInfo.
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
 * Send the interest through the transport, read the entire response and call
 * onData, onTimeout or onNetworkNack as described below.
 * There are two forms of expressInterest. The first form takes the exact
 * interest (including lifetime):
 * expressInterest(interest, onData [, onTimeout] [, onNetworkNack] [, wireFormat]).
 * The second form creates the interest from a name and optional interest template:
 * expressInterest(name [, template], onData [, onTimeout] [, onNetworkNack] [, wireFormat]).
 * @param {Interest} interest The Interest to send which includes the interest lifetime for the timeout.
 * @param {function} onData When a matching data packet is received, this calls onData(interest, data) where
 * interest is the interest given to expressInterest and data is the received
 * Data object. NOTE: You must not change the interest object - if you need to
 * change it then make a copy.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onTimeout (optional) If the interest times out according to the interest lifetime,
 *   this calls onTimeout(interest) where:
 *   interest is the interest given to expressInterest.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onNetworkNack (optional) When a network Nack packet for the
 * interest is received and onNetworkNack is not null, this calls
 * onNetworkNack(interest, networkNack) and does not call onTimeout. interest is
 * the sent Interest and networkNack is the received NetworkNack. If
 * onNetworkNack is supplied, then onTimeout must be supplied too. However, if a
 * network Nack is received and onNetworkNack is null, do nothing and wait for
 * the interest to time out. (Therefore, an application which does not yet
 * process a network Nack reason treats a Nack the same as a timeout.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {Name} name The Name for the interest. (only used for the second form of expressInterest).
 * @param {Interest} template (optional) If not omitted, copy the interest selectors from this Interest.
 * If omitted, use a default interest lifetime. (only used for the second form of expressInterest).
 * @param {WireFormat} (optional) A WireFormat object used to encode the message.
 * If omitted, use WireFormat.getDefaultWireFormat().
 * @return {number} The pending interest ID which can be used with removePendingInterest.
 * @throws Error If the encoded interest size exceeds Face.getMaxNdnPacketSize().
 */
Face.prototype.expressInterest = function
  (interestOrName, arg2, arg3, arg4, arg5, arg6)
{
  var interest;
  if (typeof interestOrName === 'object' && interestOrName instanceof Interest)
    // Just use a copy of the interest.
    interest = new Interest(interestOrName);
  else {
    // The first argument is a name. Make the interest from the name and possible template.
    if (arg2 && typeof arg2 === 'object' && arg2 instanceof Interest) {
      var template = arg2;
      // Copy the template.
      interest = new Interest(template);
      interest.setName(interestOrName);

      // Shift the remaining args to be processed below.
      arg2 = arg3;
      arg3 = arg4;
      arg4 = arg5;
      arg5 = arg6;
    }
    else {
      // No template.
      interest = new Interest(interestOrName);
      interest.setInterestLifetimeMilliseconds(4000);   // default interest timeout
    }
  }

  var onData = arg2;
  var onTimeout;
  var onNetworkNack;
  var wireFormat;
  // arg3,       arg4,          arg5 may be:
  // OnTimeout,  OnNetworkNack, WireFormat
  // OnTimeout,  OnNetworkNack, null
  // OnTimeout,  WireFormat,    null
  // OnTimeout,  null,          null
  // WireFormat, null,          null
  // null,       null,          null
  if (typeof arg3 === "function")
    onTimeout = arg3;
  else
    onTimeout = function() {};

  if (typeof arg4 === "function")
    onNetworkNack = arg4;
  else
    onNetworkNack = null;

  if (arg3 instanceof WireFormat)
    wireFormat = arg3;
  else if (arg4 instanceof WireFormat)
    wireFormat = arg4;
  else if (arg5 instanceof WireFormat)
    wireFormat = arg5;
  else
    wireFormat = WireFormat.getDefaultWireFormat();

  var pendingInterestId = this.getNextEntryId();

  // Set the nonce in our copy of the Interest so it is saved in the PIT.
  interest.setNonce(Face.nonceTemplate_);
  interest.refreshNonce();

  if (this.connectionInfo == null) {
    if (this.getConnectionInfo == null)
      console.log('ERROR: connectionInfo is NOT SET');
    else {
      var thisFace = this;
      this.connectAndExecute(function() {
        thisFace.reconnectAndExpressInterest
          (pendingInterestId, interest, onData, onTimeout, onNetworkNack,
           wireFormat);
      });
    }
  }
  else
    this.reconnectAndExpressInterest
      (pendingInterestId, interest, onData, onTimeout, onNetworkNack, wireFormat);

  return pendingInterestId;
};

/**
 * If the host and port are different than the ones in this.transport, then call
 *   this.transport.connect to change the connection (or connect for the first time).
 * Then call expressInterestHelper.
 */
Face.prototype.reconnectAndExpressInterest = function
  (pendingInterestId, interest, onData, onTimeout, onNetworkNack, wireFormat)
{
  var thisFace = this;
  if (!this.connectionInfo.equals(this.transport.connectionInfo) || this.readyStatus === Face.UNOPEN) {
    this.readyStatus = Face.OPEN_REQUESTED;
    this.onConnectedCallbacks.push
      (function() {
        thisFace.expressInterestHelper
          (pendingInterestId, interest, onData, onTimeout, onNetworkNack,
           wireFormat);
      });

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
        (function() {
          thisFace.expressInterestHelper
            (pendingInterestId, interest, onData, onTimeout, onNetworkNack,
             wireFormat);
        });
    else if (this.readyStatus === Face.OPENED)
      this.expressInterestHelper
        (pendingInterestId, interest, onData, onTimeout, onNetworkNack,
         wireFormat);
    else
      throw new Error
        ("reconnectAndExpressInterest: unexpected connection is not opened");
  }
};

/**
 * Do the work of reconnectAndExpressInterest once we know we are connected.
 * Add the PendingInterest and call this.transport.send to send the interest.
 */
Face.prototype.expressInterestHelper = function
  (pendingInterestId, interest, onData, onTimeout, onNetworkNack, wireFormat)
{
  if (this.pendingInterestTable_.add
      (pendingInterestId, interest, onData, onTimeout, onNetworkNack) == null)
    // removePendingInterest was already called with the pendingInterestId.
    return;

  // Special case: For timeoutPrefix we don't actually send the interest.
  if (!this.timeoutPrefix.match(interest.getName())) {
    var binaryInterest = interest.wireEncode(wireFormat);
    if (binaryInterest.size() > Face.getMaxNdnPacketSize())
      throw new Error
        ("The encoded interest size exceeds the maximum limit getMaxNdnPacketSize()");

    this.transport.send(binaryInterest.buf());
  }
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
  this.pendingInterestTable_.removePendingInterest(pendingInterestId);
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
 * @param {function} onComplete (optional) This calls onComplete() when complete.
 * If omitted, block until complete. (Some crypto/database libraries only use a
 * callback, so onComplete is required to use these.)
 */
Face.prototype.makeCommandInterest = function(interest, wireFormat, onComplete)
{
  onComplete = (typeof wireFormat === "function") ? wireFormat : onComplete;
  wireFormat = (typeof wireFormat === "function" || !wireFormat) ?
                 WireFormat.getDefaultWireFormat() : wireFormat;
  this.nodeMakeCommandInterest
    (interest, this.commandKeyChain, this.commandCertificateName, wireFormat,
     onComplete);
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
 * @param {function} onComplete (optional) This calls onComplete() when complete.
 * (Some crypto/database libraries only use a callback, so onComplete is
 * required to use these.)
 */
Face.prototype.nodeMakeCommandInterest = function
  (interest, keyChain, certificateName, wireFormat, onComplete)
{
  this.commandInterestGenerator.generate
    (interest, keyChain, certificateName, wireFormat, onComplete);
};

/**
 * Register prefix with the connected NDN hub and call onInterest when a
 * matching interest is received. To register a prefix with NFD, you must
 * first call setCommandSigningInfo.
 * This uses the form:
 * @param {Name} prefix The Name prefix.
 * @param {function} onInterest (optional) If not null, this creates an interest
 * filter from prefix so that when an Interest is received which matches the
 * filter, this calls
 * onInterest(prefix, interest, face, interestFilterId, filter).
 * NOTE: You must not change the prefix object - if you need to change it then
 * make a copy. If onInterest is null, it is ignored and you must call
 * setInterestFilter.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onRegisterFailed If register prefix fails for any reason,
 * this calls onRegisterFailed(prefix) where:
 *   prefix is the prefix given to registerPrefix.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onRegisterSuccess (optional) When this receives a success
 * message, this calls onRegisterSuccess(prefix, registeredPrefixId) where
 * prefix is the prefix given to registerPrefix and registeredPrefixId is
 * the value retured by registerPrefix. If onRegisterSuccess is null or omitted,
 * this does not use it. (The onRegisterSuccess parameter comes after
 * onRegisterFailed because it can be null or omitted, unlike onRegisterFailed.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {ForwardingFlags} flags (optional) The ForwardingFlags object for
 * finer control of which interests are forward to the application. If omitted,
 * use the default flags defined by the default ForwardingFlags constructor.
 * @return {number} The registered prefix ID which can be used with
 * removeRegisteredPrefix.
 */
Face.prototype.registerPrefix = function
  (prefix, onInterest, onRegisterFailed, onRegisterSuccess, flags, wireFormat)
{
  // Temporarlity reassign to resolve the different overloaded forms.
  var arg4 = onRegisterSuccess;
  var arg5 = flags;
  var arg6 = wireFormat;
  // arg4, arg5, arg6 may be:
  // OnRegisterSuccess, ForwardingFlags, WireFormat
  // OnRegisterSuccess, ForwardingFlags, null
  // OnRegisterSuccess, WireFormat,      null
  // OnRegisterSuccess, null,            null
  // ForwardingFlags,   WireFormat,      null
  // ForwardingFlags,   null,            null
  // WireFormat,        null,            null
  // null,              null,            null
  if (typeof arg4 === "function")
    onRegisterSuccess = arg4;
  else
    onRegisterSuccess = null;

  if (arg4 instanceof ForwardingFlags)
    flags = arg4;
  else if (arg5 instanceof ForwardingFlags)
    flags = arg5;
  else
    flags = new ForwardingFlags();

  if (arg4 instanceof WireFormat)
    wireFormat = arg4;
  else if (arg5 instanceof WireFormat)
    wireFormat = arg5;
  else if (arg6 instanceof WireFormat)
    wireFormat = arg6;
  else
    wireFormat = WireFormat.getDefaultWireFormat();

  if (!onRegisterFailed)
    onRegisterFailed = function() {};

  var registeredPrefixId = this.getNextEntryId();
  var thisFace = this;
  var onConnected = function() {
    thisFace.nfdRegisterPrefix
      (registeredPrefixId, prefix, onInterest, flags, onRegisterFailed,
       onRegisterSuccess, thisFace.commandKeyChain,
       thisFace.commandCertificateName, wireFormat);
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
 * Get the practical limit of the size of a network-layer packet. If a packet
 * is larger than this, the library or application MAY drop it.
 * @return {number} The maximum NDN packet size.
 */
Face.getMaxNdnPacketSize = function() { return NdnCommon.MAX_NDN_PACKET_SIZE; };

/**
 * A RegisterResponse has onData to receive the response Data packet from the
 * register prefix interest sent to the connected NDN hub. If this gets a bad
 * response or onTimeout is called, then call onRegisterFailed.
 */
Face.RegisterResponse = function RegisterResponse
  (prefix, onRegisterFailed, onRegisterSuccess, registeredPrefixId, parent,
   onInterest)
{
  this.prefix = prefix;
  this.onRegisterFailed = onRegisterFailed;
  this.onRegisterSuccess= onRegisterSuccess;
  this.registeredPrefixId = registeredPrefixId;
  this.parent = parent;
  this.onInterest = onInterest;
};

Face.RegisterResponse.prototype.onData = function(interest, responseData)
{
  // Decode responseData.getContent() and check for a success code.
  var controlResponse = new ControlResponse();
  try {
    controlResponse.wireDecode(responseData.getContent(), TlvWireFormat.get());
  }
  catch (e) {
    // Error decoding the ControlResponse.
    if (LOG > 0)
      console.log("Register prefix failed: Error decoding the NFD response: " + e);
    if (this.onRegisterFailed) {
      try {
        this.onRegisterFailed(this.prefix);
      } catch (ex) {
        console.log("Error in onRegisterFailed: " + NdnCommon.getErrorWithStackTrace(ex));
      }
    }
    return;
  }

  // Status code 200 is "OK".
  if (controlResponse.getStatusCode() != 200) {
    if (LOG > 0)
      console.log("Register prefix failed: Expected NFD status code 200, got: " +
                  controlResponse.getStatusCode());
    if (this.onRegisterFailed) {
      try {
        this.onRegisterFailed(this.prefix);
      } catch (ex) {
        console.log("Error in onRegisterFailed: " + NdnCommon.getErrorWithStackTrace(ex));
      }
    }
    return;
  }

  // Success, so we can add to the registered prefix table.
  if (this.registeredPrefixId != 0) {
    var interestFilterId = 0;
    if (this.onInterest != null)
      // registerPrefix was called with the "combined" form that includes the
      // callback, so add an InterestFilterEntry.
      interestFilterId = this.parent.setInterestFilter
        (new InterestFilter(this.prefix), this.onInterest);

    if (!this.parent.registeredPrefixTable_.add
        (this.registeredPrefixId, this.prefix, interestFilterId)) {
      // removeRegisteredPrefix was already called with the registeredPrefixId.
      if (interestFilterId > 0)
        // Remove the related interest filter we just added.
        this.parent.unsetInterestFilter(interestFilterId);

      return;
    }
  }

  if (LOG > 2)
    console.log("Register prefix succeeded with the NFD forwarder for prefix " +
                this.prefix.toUri());
  if (this.onRegisterSuccess != null) {
    try {
      this.onRegisterSuccess(this.prefix, this.registeredPrefixId);
    } catch (ex) {
      console.log("Error in onRegisterSuccess: " + NdnCommon.getErrorWithStackTrace(ex));
    }
  }
};

/**
 * We timed out waiting for the response.
 */
Face.RegisterResponse.prototype.onTimeout = function(interest)
{
  if (LOG > 2)
    console.log("Timeout for NFD register prefix command.");
  if (this.onRegisterFailed) {
    try {
      this.onRegisterFailed(this.prefix);
    } catch (ex) {
      console.log("Error in onRegisterFailed: " + NdnCommon.getErrorWithStackTrace(ex));
    }
  }
};

/**
 * Do the work of registerPrefix to register with NFD.
 * @param {number} registeredPrefixId The Face.getNextEntryId() which
 * registerPrefix got so it could return it to the caller. If this is 0, then
 * don't add to registeredPrefixTable (assuming it has already been done).
 * @param {Name} prefix
 * @param {function} onInterest
 * @param {ForwardingFlags} flags
 * @param {function} onRegisterFailed
 * @param {function} onRegisterSuccess
 * @param {KeyChain} commandKeyChain
 * @param {Name} commandCertificateName
 * @param {WireFormat} wireFormat
 */
Face.prototype.nfdRegisterPrefix = function
  (registeredPrefixId, prefix, onInterest, flags, onRegisterFailed,
   onRegisterSuccess, commandKeyChain, commandCertificateName, wireFormat)
{
  if (commandKeyChain == null)
      throw new Error
        ("registerPrefix: The command KeyChain has not been set. You must call setCommandSigningInfo.");
  if (commandCertificateName.size() == 0)
      throw new Error
        ("registerPrefix: The command certificate name has not been set. You must call setCommandSigningInfo.");

  var controlParameters = new ControlParameters();
  controlParameters.setName(prefix);
  controlParameters.setForwardingFlags(flags);

  // Make the callback for this.isLocal().
  var thisFace = this;
  var onIsLocalResult = function(isLocal) {
    var commandInterest = new Interest();
    if (isLocal) {
      commandInterest.setName(new Name("/localhost/nfd/rib/register"));
      // The interest is answered by the local host, so set a short timeout.
      commandInterest.setInterestLifetimeMilliseconds(2000.0);
    }
    else {
      commandInterest.setName(new Name("/localhop/nfd/rib/register"));
      // The host is remote, so set a longer timeout.
      commandInterest.setInterestLifetimeMilliseconds(4000.0);
    }
    // NFD only accepts TlvWireFormat packets.
    commandInterest.getName().append
      (controlParameters.wireEncode(TlvWireFormat.get()));
    thisFace.nodeMakeCommandInterest
      (commandInterest, commandKeyChain, commandCertificateName,
       TlvWireFormat.get(), function() {
      // Send the registration interest.
      var response = new Face.RegisterResponse
         (prefix, onRegisterFailed, onRegisterSuccess, registeredPrefixId,
          thisFace, onInterest);
      thisFace.reconnectAndExpressInterest
        (null, commandInterest, response.onData.bind(response),
         response.onTimeout.bind(response), null, wireFormat);
    });
  };

  this.isLocal
    (onIsLocalResult,
     function(message) {
       if (LOG > 0)
         console.log("Error in Transport.isLocal: " + message);
       if (onRegisterFailed) {
         try {
           onRegisterFailed(prefix);
         } catch (ex) {
           console.log("Error in onRegisterFailed: " + NdnCommon.getErrorWithStackTrace(ex));
         }
       }
     });
};

/**
 * Remove the registered prefix entry with the registeredPrefixId from the
 * registered prefix table. This does not affect another registered prefix with
 * a different registeredPrefixId, even if it has the same prefix name. If an
 * interest filter was automatically created by registerPrefix, also remove it.
 * If there is no entry with the registeredPrefixId, do nothing.
 *
 * @param {number} registeredPrefixId The ID returned from registerPrefix.
 */
Face.prototype.removeRegisteredPrefix = function(registeredPrefixId)
{
  this.registeredPrefixTable_.removeRegisteredPrefix(registeredPrefixId);
};

/**
 * Add an entry to the local interest filter table to call the onInterest
 * callback for a matching incoming Interest. This method only modifies the
 * library's local callback table and does not register the prefix with the
 * forwarder. It will always succeed. To register a prefix with the forwarder,
 * use registerPrefix. There are two forms of setInterestFilter.
 * The first form uses the exact given InterestFilter:
 * setInterestFilter(filter, onInterest).
 * The second form creates an InterestFilter from the given prefix Name:
 * setInterestFilter(prefix, onInterest).
 * @param {InterestFilter} filter The InterestFilter with a prefix and optional
 * regex filter used to match the name of an incoming Interest. This makes a
 * copy of filter.
 * @param {Name} prefix The Name prefix used to match the name of an incoming
 * Interest.
 * @param {function} onInterest When an Interest is received which matches the
 * filter, this calls onInterest(prefix, interest, face, interestFilterId, filter).
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 */
Face.prototype.setInterestFilter = function(filterOrPrefix, onInterest)
{
  var interestFilterId = this.getNextEntryId();
  this.interestFilterTable_.setInterestFilter
    (interestFilterId, new InterestFilter(filterOrPrefix), onInterest, this);
  return interestFilterId;
};

/**
 * Remove the interest filter entry which has the interestFilterId from the
 * interest filter table. This does not affect another interest filter with a
 * different interestFilterId, even if it has the same prefix name. If there is
 * no entry with the interestFilterId, do nothing.
 * @param {number} interestFilterId The ID returned from setInterestFilter.
 */
Face.prototype.unsetInterestFilter = function(interestFilterId)
{
  this.interestFilterTable_.unsetInterestFilter(interestFilterId);
};

/**
 * The OnInterest callback calls this to put a Data packet which satisfies an
 * Interest.
 * @param {Data} data The Data packet which satisfies the interest.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the Data packet. If omitted, use WireFormat.getDefaultWireFormat().
 * @throws Error If the encoded Data packet size exceeds getMaxNdnPacketSize().
 */
Face.prototype.putData = function(data, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());

  var encoding = data.wireEncode(wireFormat);
  if (encoding.size() > Face.getMaxNdnPacketSize())
    throw new Error
      ("The encoded Data packet size exceeds the maximum limit getMaxNdnPacketSize()");

  this.transport.send(encoding.buf());
};

/**
 * Send the encoded packet out through the transport.
 * @param {Buffer} encoding The Buffer with the encoded packet to send.
 * @throws Error If the encoded packet size exceeds getMaxNdnPacketSize().
 */
Face.prototype.send = function(encoding)
{
  if (encoding.length > Face.getMaxNdnPacketSize())
    throw new Error
      ("The encoded packet size exceeds the maximum limit getMaxNdnPacketSize()");

  this.transport.send(encoding);
};

/**
 * Check if the face is local based on the current connection through the
 * Transport; some Transport may cause network I/O (e.g. an IP host name lookup).
 * @param {function} onResult On success, this calls onResult(isLocal) where
 * isLocal is true if the host is local, false if not. We use callbacks because
 * this may need to do network I/O (e.g. an IP host name lookup).
 * @param {function} onError On failure for DNS lookup or other error, this
 * calls onError(message) where message is an error string.
 */
Face.prototype.isLocal = function(onResult, onError)
{
  // TODO: How to call transport.isLocal when this.connectionInfo is null? (This
  // happens when the application does not supply a host but relies on the
  // getConnectionInfo function to select a host.) For now return true to keep
  // the same behavior from before we added Transport.isLocal.
  if (this.connectionInfo == null)
    onResult(false);
  else
    this.transport.isLocal(this.connectionInfo, onResult, onError);
};

/**
 * This is called when an entire element is received, such as a Data or Interest.
 */
Face.prototype.onReceivedElement = function(element)
{
  if (LOG > 3) console.log('Complete element received. Length ' + element.length + '. Start decoding.');

  var lpPacket = null;
  if (element[0] == Tlv.LpPacket_LpPacket) {
    // Decode the LpPacket and replace element with the fragment.
    lpPacket = new LpPacket();
    // Set copy false so that the fragment is a slice which will be copied below.
    // The header fields are all integers and don't need to be copied.
    TlvWireFormat.get().decodeLpPacket(lpPacket, element, false);
    element = lpPacket.getFragmentWireEncoding().buf();
  }

  // First, decode as Interest or Data.
  var interest = null;
  var data = null;
  if (element[0] == Tlv.Interest || element[0] == Tlv.Data) {
    var decoder = new TlvDecoder (element);
    if (decoder.peekType(Tlv.Interest, element.length)) {
      interest = new Interest();
      interest.wireDecode(element, TlvWireFormat.get());

      if (lpPacket != null)
        interest.setLpPacket(lpPacket);
    }
    else if (decoder.peekType(Tlv.Data, element.length)) {
      data = new Data();
      data.wireDecode(element, TlvWireFormat.get());

      if (lpPacket != null)
        data.setLpPacket(lpPacket);
    }
  }

  if (lpPacket !== null) {
    // We have decoded the fragment, so remove the wire encoding to save memory.
    lpPacket.setFragmentWireEncoding(new Blob());

    var networkNack = NetworkNack.getFirstHeader(lpPacket);
    if (networkNack != null) {
      if (interest == null)
        // We got a Nack but not for an Interest, so drop the packet.
        return;

      var pitEntries = [];
      this.pendingInterestTable_.extractEntriesForNackInterest(interest, pitEntries);
      for (var i = 0; i < pitEntries.length; ++i) {
        var pendingInterest = pitEntries[i];
        try {
          pendingInterest.getOnNetworkNack()(pendingInterest.getInterest(), networkNack);
        } catch (ex) {
          console.log("Error in onNetworkNack: " + NdnCommon.getErrorWithStackTrace(ex));
        }
      }

      // We have processed the network Nack packet.
      return;
    }
  }

  // Now process as Interest or Data.
  if (interest !== null) {
    if (LOG > 3) console.log('Interest packet received.');
    this.dispatchInterest_(interest);
  }
  else if (data !== null) {
    if (LOG > 3) console.log('Data packet received.');
    this.satisfyPendingInterests_(data);
  }
};

/**
 * Call the OnInterest callback for all entries in the interestFilterTable_
 * that match the interest.
 * @param {Interest} interest The Interest to match.
 */
Face.prototype.dispatchInterest_ = function(interest)
{
  // Call all interest filter callbacks which match.
  var matchedFilters = [];
  this.interestFilterTable_.getMatchedFilters(interest, matchedFilters);
  for (var i = 0; i < matchedFilters.length; ++i) {
    var entry = matchedFilters[i];
    if (LOG > 3)
      console.log("Found interest filter for " + interest.getName().toUri());
    try {
      entry.getOnInterest()
        (entry.getFilter().getPrefix(), interest, this,
         entry.getInterestFilterId(), entry.getFilter());
    } catch (ex) {
      console.log("Error in onInterest: " + NdnCommon.getErrorWithStackTrace(ex));
    }
  }
};

/**
 * Extract entries from the pendingInterestTable_ which match data, and call
 * each OnData callback.
 * @param {Data} data The Data packet to match.
 * @return {boolean} True if the data matched an entry in the
 * pendingInterestTable_.
 */
Face.prototype.satisfyPendingInterests_ = function(data)
{
  var hasMatch = false;

  var pendingInterests = [];
  this.pendingInterestTable_.extractEntriesForExpressedInterest
    (data, pendingInterests);
  // Process each matching PIT entry (if any).
  for (var i = 0; i < pendingInterests.length; ++i) {
    var pendingInterest = pendingInterests[i];
    hasMatch = true;
    try {
      pendingInterest.getOnData()(pendingInterest.getInterest(), data);
    } catch (ex) {
      console.log("Error in onData: " + NdnCommon.getErrorWithStackTrace(ex));
    }
  }

  return hasMatch;
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

  this.reconnectAndExpressInterest
    (null, interest,
     function(localInterest, localData) {
        // The host is alive, so cancel the timeout and continue with onConnected().
        clearTimeout(timerID);

        if (LOG>0)
          console.log("connectAndExecute: connected to host " + thisFace.host);
        onConnected();
     },
     function(localInterest) { /* Ignore timeout */ },
     null, WireFormat.getDefaultWireFormat());
};

/**
 * This is called by the Transport when the connection is closed by the remote host.
 */
Face.prototype.closeByTransport = function()
{
  this.readyStatus = Face.CLOSED;
  this.onclose();
};

Face.nonceTemplate_ = new Blob(new Buffer(4), false);
