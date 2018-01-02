/**
 * Copyright (C) 2013-2018 Regents of the University of California.
 * @author: Wentao Shang
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
var ElementReader = require('../encoding/element-reader.js').ElementReader; /** @ignore */
var LOG = require('../log.js').Log.LOG; /** @ignore */
var Transport = require('./transport.js').Transport; /** @ignore */
var Face;

/**
 * @constructor
 */
var WebSocketTransport = function WebSocketTransport()
{
  // Call the base constructor.
  Transport.call(this);

  if (!WebSocket)
    throw new Error("WebSocket support is not available on this platform.");

  this.ws = null;
  this.connectionInfo = null; // Read by Face.
  this.elementReader = null;
  this.defaultGetConnectionInfo = Face.makeShuffledHostGetConnectionInfo
    (["A.ws.ndn.ucla.edu", "B.ws.ndn.ucla.edu", "C.ws.ndn.ucla.edu", "D.ws.ndn.ucla.edu",
      "E.ws.ndn.ucla.edu", "F.ws.ndn.ucla.edu", "G.ws.ndn.ucla.edu", "H.ws.ndn.ucla.edu",
      "I.ws.ndn.ucla.edu", "J.ws.ndn.ucla.edu", "K.ws.ndn.ucla.edu", "L.ws.ndn.ucla.edu",
      "M.ws.ndn.ucla.edu", "N.ws.ndn.ucla.edu"],
     9696,
     function(host, port) { return new WebSocketTransport.ConnectionInfo(host, port); });
};

WebSocketTransport.prototype = new Transport();
WebSocketTransport.prototype.name = "WebSocketTransport";

WebSocketTransport.importFace = function(face){
  Face = face;
};

exports.WebSocketTransport = WebSocketTransport;

/**
 * Create a new WebSocketTransport.ConnectionInfo which extends
 * Transport.ConnectionInfo to hold the host and port info for the WebSocket
 * connection.
 * @param {string} host The host for the connection. However, if the host string
 * begins with "ws:" or "wss:", then ignore port and use the string as the full
 * endpoint URI.
 * @param {number} port (optional) The port number for the connection. If
 * omitted, use 9696.
 */
WebSocketTransport.ConnectionInfo = function WebSocketTransportConnectionInfo
  (host, port)
{
  // Call the base constructor.
  Transport.ConnectionInfo .call(this);

  port = (port !== undefined ? port : 9696);

  this.host = host;
  this.port = port;
};

WebSocketTransport.ConnectionInfo.prototype = new Transport.ConnectionInfo();
WebSocketTransport.ConnectionInfo.prototype.name = "WebSocketTransport.ConnectionInfo";

/**
 * Check if the fields of this WebSocketTransport.ConnectionInfo equal the other
 * WebSocketTransport.ConnectionInfo.
 * @param {WebSocketTransport.ConnectionInfo} The other object to check.
 * @return {boolean} True if the objects have equal fields, false if not.
 */
WebSocketTransport.ConnectionInfo.prototype.equals = function(other)
{
  if (other == null || other.host == undefined || other.port == undefined)
    return false;
  return this.host == other.host && this.port == other.port;
};

WebSocketTransport.ConnectionInfo.prototype.toString = function()
{
  if (this.hostIsUri())
    return "{ uri: " + this.host + " }";
  else
    return "{ host: " + this.host + ", port: " + this.port + " }";
};

WebSocketTransport.ConnectionInfo.prototype.hostIsUri = function()
{
  return this.host.substr(0, 3) == "ws:" ||
         this.host.substr(0, 4) == "wss:";
}

/**
 * Determine whether this transport connecting according to connectionInfo is to
 * a node on the current machine. WebSocket transports are always non-local.
 * @param {WebSocketTransport.ConnectionInfo} connectionInfo This is ignored.
 * @param {function} onResult This calls onResult(false) because WebSocket
 * transports are always non-local.
 * @param {function} onError This is ignored.
 */
WebSocketTransport.prototype.isLocal = function(connectionInfo, onResult, onError)
{
  onResult(false);
};

/**
 * Connect to a WebSocket according to the info in connectionInfo. Listen on
 * the port to read an entire packet element and call
 * elementListener.onReceivedElement(element). Note: this connect method
 * previously took a Face object which is deprecated and renamed as the method
 * connectByFace.
 * @param {WebSocketTransport.ConnectionInfo} connectionInfo A
 * WebSocketTransport.ConnectionInfo.
 * @param {object} elementListener The elementListener with function
 * onReceivedElement which must remain valid during the life of this object.
 * @param {function} onopenCallback Once connected, call onopenCallback().
 * @param {function} onclosedCallback (optional) If the connection is closed by
 * the remote host, call onclosedCallback(). If omitted or null, don't call it.
 */
WebSocketTransport.prototype.connect = function
  (connectionInfo, elementListener, onopenCallback, onclosedCallback)
{
  this.close();

  var uri = connectionInfo.hostIsUri() ?
    connectionInfo.host : 'ws://' + connectionInfo.host + ':' + connectionInfo.port;
  this.ws = new WebSocket(uri);
  if (LOG > 0) console.log('ws connection created.');
    this.connectionInfo = connectionInfo;

  this.ws.binaryType = "arraybuffer";

  this.elementReader = new ElementReader(elementListener);
  var self = this;
  this.ws.onmessage = function(ev) {
    var result = ev.data;
    //console.log('RecvHandle called.');

    if (result == null || result == undefined || result == "") {
      console.log('INVALID ANSWER');
    }
    else if (result instanceof ArrayBuffer) {
      // The Buffer constructor expects an instantiated array.
      var bytearray = new Buffer(new Uint8Array(result));

      if (LOG > 3) console.log('BINARY RESPONSE IS ' + bytearray.toString('hex'));

      try {
        // Find the end of the element and call onReceivedElement.
        self.elementReader.onReceivedData(bytearray);
      } catch (ex) {
        console.log("NDN.ws.onmessage exception: " + ex);
        return;
      }
    }
  }

  this.ws.onopen = function(ev) {
    if (LOG > 3) console.log(ev);
    if (LOG > 3) console.log('ws.onopen: WebSocket connection opened.');
    if (LOG > 3) console.log('ws.onopen: ReadyState: ' + this.readyState);
    // Face.registerPrefix will fetch the ndndid when needed.

    onopenCallback();
  }

  this.ws.onerror = function(ev) {
    console.log('ws.onerror: ReadyState: ' + this.readyState);
    console.log(ev);
    console.log('ws.onerror: WebSocket error: ' + ev.data);
  }

  this.ws.onclose = function(ev) {
    console.log('ws.onclose: WebSocket connection closed.');
    self.ws = null;

    if (onclosedCallback != null)
      onclosedCallback();
  }
};

/**
 * @deprecated This is deprecated. You should not call Transport.connect
 * directly, since it is called by Face methods.
 */
WebSocketTransport.prototype.connectByFace = function(face, onopenCallback)
{
  this.connect
    (face.connectionInfo, face, onopenCallback,
     function() { face.closeByTransport(); });
};

/**
 * Send the Uint8Array data.
 */
WebSocketTransport.prototype.send = function(data)
{
  if (this.ws != null) {
    // If we directly use data.buffer to feed ws.send(),
    // WebSocket may end up sending a packet with 10000 bytes of data.
    // That is, WebSocket will flush the entire buffer
    // regardless of the offset of the Uint8Array. So we have to create
    // a new Uint8Array buffer with just the right size and copy the
    // content from binaryInterest to the new buffer.
    //    ---Wentao
    var bytearray = new Uint8Array(data.length);
    bytearray.set(data);
    this.ws.send(bytearray.buffer);
    if (LOG > 3) console.log('ws.send() returned.');
  }
  else
    console.log('WebSocket connection is not established.');
};

/**
 * Close the connection.
 */
WebSocketTransport.prototype.close = function()
{
  if (this.ws != null)
    delete this.ws;
}

