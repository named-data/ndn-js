/**
 * Copyright (C) 2013-2018 Regents of the University of California.
 * @author: Wentao Shang
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

/** @ignore */
var dns = require('dns'); /** @ignore */
var ElementReader = require('../encoding/element-reader.js').ElementReader; /** @ignore */
var LOG = require('../log.js').Log.LOG; /** @ignore */
var Transport = require('./transport.js').Transport;

/**
 * A TcpTransport connects to the forwarder using TCP for Node.js.
 * @constructor
 */
var TcpTransport = function TcpTransport()
{
  // Call the base constructor.
  Transport.call(this);

  this.socket = null;
  this.sock_ready = false;
  this.elementReader = null;
  this.connectionInfo = null; // Read by Face.
  this.isLocalConnectionInfo = null; // Used by isLocal to cache results.
  this.isLocalResult = false;

  this.defaultGetConnectionInfo = require('../face.js').Face.makeShuffledHostGetConnectionInfo
    (["A.hub.ndn.ucla.edu", "B.hub.ndn.ucla.edu", "C.hub.ndn.ucla.edu", "D.hub.ndn.ucla.edu",
      "E.hub.ndn.ucla.edu", "F.hub.ndn.ucla.edu", "G.hub.ndn.ucla.edu", "H.hub.ndn.ucla.edu",
      "I.hub.ndn.ucla.edu", "J.hub.ndn.ucla.edu", "K.hub.ndn.ucla.edu"],
     6363,
     function(host, port) { return new TcpTransport.ConnectionInfo(host, port); });
};

TcpTransport.prototype = new Transport();
TcpTransport.prototype.name = "TcpTransport";

TcpTransport.importFace = function(){};

exports.TcpTransport = TcpTransport;

/**
 * Create a new TcpTransport.ConnectionInfo which extends
 * Transport.ConnectionInfo to hold the host and port info for the TCP
 * connection.
 * @param {string} host The host for the connection.
 * @param {number} port (optional) The port number for the connection. If
 * omitted, use 6363.
 */
TcpTransport.ConnectionInfo = function TcpTransportConnectionInfo(host, port)
{
  // Call the base constructor.
  Transport.ConnectionInfo .call(this);

  port = (port !== undefined ? port : 6363);

  this.host = host;
  this.port = port;
};

TcpTransport.ConnectionInfo.prototype = new Transport.ConnectionInfo();
TcpTransport.ConnectionInfo.prototype.name = "TcpTransport.ConnectionInfo";

/**
 * Check if the fields of this TcpTransport.ConnectionInfo equal the other
 * TcpTransport.ConnectionInfo.
 * @param {TcpTransport.ConnectionInfo} The other object to check.
 * @return {boolean} True if the objects have equal fields, false if not.
 */
TcpTransport.ConnectionInfo.prototype.equals = function(other)
{
  if (other == null || other.host == undefined || other.port == undefined)
    return false;
  return this.host == other.host && this.port == other.port;
};

TcpTransport.ConnectionInfo.prototype.toString = function()
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
TcpTransport.prototype.isLocal = function(connectionInfo, onResult, onError)
{
  if (this.isLocalConnectionInfo == null ||
      this.isLocalConnectionInfo.host != connectionInfo.host) {
    // Do the async DNS lookup.
    var thisTransport = this;
    dns.lookup
      (connectionInfo.host,
       function(err, addresses, family) {
         if (err != null)
           onError(err.toString());
         else {
           if (family == 4)
             // IPv4
             thisTransport.isLocalResult = (addresses.substr(0, 4) == "127.");
           else
             // IPv6
             thisTransport.isLocalResult = (addresses == "::1");
         }

         // Cache the result in this.isLocalResult and save
         // this.isLocalConnectionInfo for next time.
         thisTransport.isLocalConnectionInfo = connectionInfo;

         onResult(thisTransport.isLocalResult);
       });
  }
  else
    // Use the cached result.
    onResult(this.isLocalResult);
};

/**
 * Connect to a TCP socket according to the info in connectionInfo. Listen on
 * the port to read an entire packet element and call
 * elementListener.onReceivedElement(element). Note: this connect method
 * previously took a Face object which is deprecated and renamed as the method
 * connectByFace.
 * @param {TcpTransport.ConnectionInfo} connectionInfo A
 * TcpTransport.ConnectionInfo with the host and port.
 * @param {object} elementListener The elementListener with function
 * onReceivedElement which must remain valid during the life of this object.
 * @param {function} onopenCallback Once connected, call onopenCallback().
 * @param {function} onclosedCallback (optional) If the connection is closed by
 * the remote host, call onclosedCallback(). If omitted or null, don't call it.
 */
TcpTransport.prototype.connect = function
  (connectionInfo, elementListener, onopenCallback, onclosedCallback)
{
  if (this.socket != null)
    delete this.socket;

  this.elementReader = new ElementReader(elementListener);

  var net = require('net');
  this.socket = new net.Socket();

  var self = this;

  this.socket.on('data', function(data) {
    if (typeof data == 'object') {
      // Make a copy of data (maybe a Buffer or a String)
      var buf = new Buffer(data);
      try {
        // Find the end of the packet element and call onReceivedElement.
        self.elementReader.onReceivedData(buf);
      } catch (ex) {
        console.log("NDN.TcpTransport.ondata exception: " + ex);
        return;
      }
    }
  });

  this.socket.on('connect', function() {
    if (LOG > 3) console.log('socket.onopen: TCP connection opened.');

    self.sock_ready = true;

    onopenCallback();
  });

  this.socket.on('error', function() {
    if (LOG > 3) console.log('socket.onerror: TCP socket error');
  });

  this.socket.on('close', function() {
    if (LOG > 3) console.log('socket.onclose: TCP connection closed.');

    self.socket = null;

    if (onclosedCallback != null)
      onclosedCallback();
  });

  this.socket.connect({host: connectionInfo.host, port: connectionInfo.port});
  this.connectionInfo = connectionInfo;
};

/**
 * @deprecated This is deprecated. You should not call Transport.connect
 * directly, since it is called by Face methods.
 */
TcpTransport.prototype.connectByFace = function(face, onopenCallback)
{
  this.connect
    (face.connectionInfo, face, onopenCallback,
     function() { face.closeByTransport(); });
};

/**
 * Send data.
 */
TcpTransport.prototype.send = function(/*Buffer*/ data)
{
  if (this.sock_ready)
    this.socket.write(data);
  else
    console.log('TCP connection is not established.');
};

/**
 * Close transport
 */
TcpTransport.prototype.close = function()
{
  this.socket.end();
  if (LOG > 3) console.log('TCP connection closed.');
};
