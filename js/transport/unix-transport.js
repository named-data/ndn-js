/**
 * Copyright (C) 2014-2018 Regents of the University of California.
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
var ElementReader = require('../encoding/element-reader.js').ElementReader; /** @ignore */
var LOG = require('../log.js').Log.LOG; /** @ignore */
var Transport = require('./transport.js').Transport;

/**
 * A UnixTransport connects to the forwarder using a Unix socket for Node.js.
 * @constructor
 */
var UnixTransport = function UnixTransport()
{
  // Call the base constructor.
  Transport.call(this);

  this.socket = null;
  this.sock_ready = false;
  this.elementReader = null;
  this.connectionInfo = null; // Read by Face.

  // There is no "round robin" search for the local forwarder.
  this.defaultGetConnectionInfo = null;
};

UnixTransport.prototype = new Transport();
UnixTransport.prototype.name = "UnixTransport";

exports.UnixTransport = UnixTransport;

/**
 * Create a new UnixTransport.ConnectionInfo which extends
 * Transport.ConnectionInfo to hold the socket file path for the Unix
 * socket connection.
 * @param {string} filePath The file path of the Unix socket file.
 */
UnixTransport.ConnectionInfo = function UnixTransportConnectionInfo(filePath)
{
  // Call the base constructor.
  Transport.ConnectionInfo .call(this);

  this.filePath = filePath;
};

UnixTransport.ConnectionInfo.prototype = new Transport.ConnectionInfo();
UnixTransport.ConnectionInfo.prototype.name = "UnixTransport.ConnectionInfo";

/**
 * Check if the fields of this UnixTransport.ConnectionInfo equal the other
 * UnixTransport.ConnectionInfo.
 * @param {UnixTransport.ConnectionInfo} The other object to check.
 * @return {boolean} True if the objects have equal fields, false if not.
 */
UnixTransport.ConnectionInfo.prototype.equals = function(other)
{
  if (other == null || other.filePath == undefined)
    return false;
  return this.filePath == other.filePath;
};

UnixTransport.ConnectionInfo.prototype.toString = function()
{
  return "{ filePath: " + this.filePath + " }";
};

/**
 * Determine whether this transport connecting according to connectionInfo is to
 * a node on the current machine. Unix transports are always local.
 * @param {UnixTransport.ConnectionInfo} connectionInfo This is ignored.
 * @param {function} onResult This calls onResult(true) because Unix transports
 * are always local.
 * @param {function} onError This is ignored.
 */
UnixTransport.prototype.isLocal = function(connectionInfo, onResult, onError)
{
  onResult(true);
};

/**
 * Connect to a Unix socket according to the info in connectionInfo. Listen on
 * the port to read an entire packet element and call
 * elementListener.onReceivedElement(element). Note: this connect method
 * previously took a Face object which is deprecated and renamed as the method
 * connectByFace.
 * @param {UnixTransport.ConnectionInfo} connectionInfo A
 * UnixTransport.ConnectionInfo with the Unix socket filePath.
 * @param {object} elementListener The elementListener with function
 * onReceivedElement which must remain valid during the life of this object.
 * @param {function} onopenCallback Once connected, call onopenCallback().
 * @param {function} onclosedCallback (optional) If the connection is closed by
 * the remote host, call onclosedCallback(). If omitted or null, don't call it.
 */
UnixTransport.prototype.connect = function
  (connectionInfo, elementListener, onopenCallback, onclosedCallback)
{
  if (this.socket != null)
    delete this.socket;

  this.elementReader = new ElementReader(elementListener);

  var net = require('net');
  this.socket = new net.createConnection(connectionInfo.filePath);

  var thisTransport = this;

  this.socket.on('data', function(data) {
    if (typeof data == 'object') {
      // Make a copy of data (maybe a Buffer or a String)
      var buf = new Buffer(data);
      try {
        // Find the end of the packet element and call onReceivedElement.
        thisTransport.elementReader.onReceivedData(buf);
      } catch (ex) {
        console.log("NDN.UnixTransport.ondata exception: " + ex);
        return;
      }
    }
  });

  this.socket.on('connect', function() {
    if (LOG > 3) console.log('socket.onopen: Unix socket connection opened.');

    thisTransport.sock_ready = true;

    onopenCallback();
  });

  this.socket.on('error', function() {
    if (LOG > 3) console.log('socket.onerror: Unix socket error');
  });

  this.socket.on('close', function() {
    if (LOG > 3) console.log('socket.onclose: Unix socket connection closed.');

    thisTransport.socket = null;

    if (onclosedCallback != null)
      onclosedCallback();
  });

  this.connectionInfo = connectionInfo;
};

/**
 * Send data.
 */
UnixTransport.prototype.send = function(/*Buffer*/ data)
{
  if (this.sock_ready)
    this.socket.write(data);
  else
    console.log('Unix socket connection is not established.');
};

/**
 * Close transport
 */
UnixTransport.prototype.close = function()
{
  this.socket.end();
  if (LOG > 3) console.log('Unix socket connection closed.');
};
