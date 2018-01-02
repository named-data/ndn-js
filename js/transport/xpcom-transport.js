/**
 * Implement getAsync and putAsync used by Face using nsISocketTransportService.
 * This is used inside Firefox XPCOM modules.
 * Copyright (C) 2013-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
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

// Assume already imported the following:
// Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");
// Components.utils.import("resource://gre/modules/NetUtil.jsm");

/**
 * @constructor
 */
var XpcomTransport = function XpcomTransport()
{
  // Call the base constructor.
  Transport.call(this);

  this.elementListener = null;
  this.socket = null; // nsISocketTransport
  this.outStream = null;
  this.connectionInfo = null; // Read by Face.
  this.httpListener = null;

  this.defaultGetConnectionInfo = Face.makeShuffledHostGetConnectionInfo
    (["A.hub.ndn.ucla.edu", "B.hub.ndn.ucla.edu", "C.hub.ndn.ucla.edu", "D.hub.ndn.ucla.edu",
      "E.hub.ndn.ucla.edu", "F.hub.ndn.ucla.edu", "G.hub.ndn.ucla.edu", "H.hub.ndn.ucla.edu",
      "I.hub.ndn.ucla.edu", "J.hub.ndn.ucla.edu", "K.hub.ndn.ucla.edu"],
     6363,
     function(host, port) { return new XpcomTransport.ConnectionInfo(host, port); });
};

XpcomTransport.prototype = new Transport();
XpcomTransport.prototype.name = "XpcomTransport";

/**
 * Create a new XpcomTransport.ConnectionInfo which extends
 * Transport.ConnectionInfo to hold the host and port info for the XPCOM
 * connection.
 * @param {string} host The host for the connection.
 * @param {number} port (optional) The port number for the connection. If
 * omitted, use 6363.
 */
XpcomTransport.ConnectionInfo = function XpcomTransportConnectionInfo(host, port)
{
  // Call the base constructor.
  Transport.ConnectionInfo .call(this);

  port = (port !== undefined ? port : 6363);

  this.host = host;
  this.port = port;
};

XpcomTransport.ConnectionInfo.prototype = new Transport.ConnectionInfo();
XpcomTransport.ConnectionInfo.prototype.name = "XpcomTransport.ConnectionInfo";

/**
 * Check if the fields of this XpcomTransport.ConnectionInfo equal the other
 * XpcomTransport.ConnectionInfo.
 * @param {XpcomTransport.ConnectionInfo} The other object to check.
 * @return {boolean} True if the objects have equal fields, false if not.
 */
XpcomTransport.ConnectionInfo.prototype.equals = function(other)
{
  if (other == null || other.host == undefined || other.port == undefined)
    return false;
  return this.host == other.host && this.port == other.port;
};

XpcomTransport.ConnectionInfo.prototype.toString = function()
{
  return "{ host: " + this.host + ", port: " + this.port + " }";
};

/**
 * Determine whether this transport connecting according to connectionInfo is to
 * a node on the current machine; results are cached. According to
 * http://redmine.named-data.net/projects/nfd/wiki/ScopeControl#local-face, TCP
 * transports with a loopback address are local. If connectionInfo contains a
 * host name, this will do a DNS lookup; otherwise this will parse the
 * IP address and examine the first octet to determine if it is a loopback
 * address (e.g. the first IPv4 octet is 127 or IPv6 is "::1").
 * @param {function} onResult On success, this calls onResult(isLocal) where
 * isLocal is true if the host is local, false if not. We use callbacks because
 * this may need to do an asynchronous DNS lookup.
 * @param {function} onError On failure for DNS lookup or other error, this
 * calls onError(message) where message is an error string.
 */
XpcomTransport.prototype.isLocal = function(connectionInfo, onResult, onError)
{
  // TODO: Use XPCOM to look up connectionInfo.getHost(). For now, only the
  // ndn-protocol Firefox add-on uses XpcomTransport, so assume the host is
  // non-local. (Also, the Firefox add-on doesn't do registerPrefix so this
  // isn't called.)
  onResult(false);
};

/**
 * Connect to a TCP socket through Xpcom according to the info in connectionInfo.
 * Listen on the port to read an entire packet element and call
 * elementListener.onReceivedElement(element). Note: this connect method
 * previously took a Face object which is deprecated and renamed as the method
 * connectByFace.
 * @param {XpcomTransport.ConnectionInfo} connectionInfo A
 * XpcomTransport.ConnectionInfo with the host and port.
 * @param {object} elementListener The elementListener with function
 * onReceivedElement which must remain valid during the life of this object.
 * @param {function} onopenCallback Once connected, call onopenCallback().
 * @param {function} onclosedCallback (optional) If the connection is closed by
 * the remote host, call onclosedCallback(). If omitted or null, don't call it.
 */
XpcomTransport.prototype.connect = function
  (connectionInfo, elementListener, onopenCallback, onclosedCallback)
{
  this.elementListener = elementListener;
  this.connectHelper(connectionInfo, elementListener);

  onopenCallback();
};

/**
 * @deprecated This is deprecated. You should not call Transport.connect
 * directly, since it is called by Face methods.
 */
XpcomTransport.prototype.connectByFace = function(face, onopenCallback)
{
  this.connect
    (face.connectionInfo, face, onopenCallback,
     function() { face.closeByTransport(); });
};

/**
 * Do the work to connect to the socket.  This replaces a previous connection
 * and sets connectionInfo.
 * @param {XpcomTransport.ConnectionInfo|object} connectionInfoOrSocketTransport
 * The connectionInfo with the host and port to connect to. However, if this is not a
 * Transport.ConnectionInfo, assume it is an nsISocketTransport which is already
 * configured for a host and port, in which case set connectionInfo to new
 * XpcomTransport.ConnectionInfo(connectionInfoOrSocketTransport.host, connectionInfoOrSocketTransport.port).
 * @param {object} elementListener The elementListener with function
 * onReceivedElement which must remain valid during the life of this object.
 * Listen on the port to read an entire element and call
 * elementListener.onReceivedElement(element).
 */
XpcomTransport.prototype.connectHelper = function
  (connectionInfoOrSocketTransport, elementListener)
{
  if (this.socket != null) {
    try {
        this.socket.close(0);
    } catch (ex) {
      console.log("XpcomTransport socket.close exception: " + ex);
    }
    this.socket = null;
  }

  var pump = Components.classes["@mozilla.org/network/input-stream-pump;1"].createInstance
        (Components.interfaces.nsIInputStreamPump);
  if (connectionInfoOrSocketTransport instanceof Transport.ConnectionInfo) {
    var connectionInfo = connectionInfoOrSocketTransport;
    var transportService = Components.classes["@mozilla.org/network/socket-transport-service;1"].getService
          (Components.interfaces.nsISocketTransportService);
    this.socket = transportService.createTransport
      (null, 0, connectionInfo.host, connectionInfo.port, null);
    if (LOG > 0) console.log('XpcomTransport: Connected to ' +
      connectionInfo.host + ":" + connectionInfo.port);
    this.connectionInfo = connectionInfo;
  }
  else if (typeof connectionInfoOrSocketTransport == 'object') {
    var socketTransport = connectionInfoOrSocketTransport;
    // Assume host is an nsISocketTransport which is already configured for a host and port.
    this.socket = socketTransport;
    this.connectionInfo = new XpcomTransport.ConnectionInfo
      (socketTransport.host, socketTransport.port);
  }
  this.outStream = this.socket.openOutputStream(1, 0, 0);

  var thisXpcomTransport = this;
  var inStream = this.socket.openInputStream(0, 0, 0);
  var dataListener = {
    elementReader: new ElementReader(elementListener),
    gotFirstData: false,

    onStartRequest: function(request, context) {
    },
    onStopRequest: function(request, context, status) {
    },
    onDataAvailable: function(request, context, _inputStream, offset, count) {
      try {
        // Use readInputStreamToString to handle binary data.
        // TODO: Can we go directly from the stream to Buffer?
        var inputString = NetUtil.readInputStreamToString(inStream, count);
        if (!this.gotFirstData) {
          // Check if the connection is from a non-NDN source.
          this.gotFirstData = true;
          if (inputString.substring(0, 4) == "GET ") {
            // Assume this is the start of an HTTP header.
            // Set elementReader null so we ignore further input.
            if (LOG > 0) console.log("XpcomTransport: Got HTTP header. Ignoring the NDN element reader.");
            this.elementReader = null;

            if (thisXpcomTransport.httpListener != null)
              thisXpcomTransport.httpListener.onHttpRequest(thisXpcomTransport, inputString);
          }
        }

        if (this.elementReader != null)
          this.elementReader.onReceivedData(DataUtils.toNumbersFromString(inputString));
      } catch (ex) {
        console.log("XpcomTransport.onDataAvailable exception: " + ex + "\n" + ex.stack);
      }
    }
  };

  pump.init(inStream, -1, -1, 0, 0, true);
  pump.asyncRead(dataListener, null);
};

/**
 * Send the data over the connection created by connect.
 */
XpcomTransport.prototype.send = function(/* Buffer */ data)
{
  if (this.socket == null || this.connectionInfo == null) {
    console.log("XpcomTransport connection is not established.");
    return;
  }

  var rawDataString = DataUtils.toString(data);
  try {
    this.outStream.write(rawDataString, rawDataString.length);
    this.outStream.flush();
  } catch (ex) {
    if (this.socket.isAlive())
      // The socket is still alive. Assume there could still be incoming data. Just throw the exception.
      throw ex;

    if (LOG > 0)
      console.log("XpcomTransport.send: Trying to reconnect to " +
        this.connectionInfo.toString() + " and resend after exception: " + ex);

    this.connectHelper(this.connectionInfo, this.elementListener);
    this.outStream.write(rawDataString, rawDataString.length);
    this.outStream.flush();
  }
};

/**
 * If the first data received on the connection is an HTTP request, call listener.onHttpRequest(transport, request)
 * where transport is this transport object and request is a string with the request.
 * @param {object} listener An object with onHttpRequest, or null to not respond to HTTP messages.
 */
XpcomTransport.prototype.setHttpListener = function(listener)
{
  this.httpListener = listener;
};
