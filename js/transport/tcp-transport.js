/** 
 * Copyright (C) 2013-2014 Regents of the University of California.
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var ElementReader = require('../encoding/element-reader.js').ElementReader;
var LOG = require('../log.js').Log.LOG;
var Transport = require('./transport.js').Transport;

/**
 * A TcpTransport connects to the forwarder using TCP for Node.js.
 */
var TcpTransport = function TcpTransport() 
{    
  // Call the base constructor.
  Transport.call(this);
  
  this.socket = null;
  this.sock_ready = false;
  this.elementReader = null;
  this.connectionInfo = null; // Read by Face.

  this.defaultGetConnectionInfo = require('../face.js').Face.makeShuffledHostGetConnectionInfo
    (["A.hub.ndn.ucla.edu", "B.hub.ndn.ucla.edu", "C.hub.ndn.ucla.edu", "D.hub.ndn.ucla.edu", 
      "E.hub.ndn.ucla.edu", "F.hub.ndn.ucla.edu", "G.hub.ndn.ucla.edu", "H.hub.ndn.ucla.edu", 
      "I.hub.ndn.ucla.edu", "J.hub.ndn.ucla.edu", "K.hub.ndn.ucla.edu"],
     6363,
     function(host, port) { return new TcpTransport.ConnectionInfo(host, port); });
};

TcpTransport.prototype = new Transport();
TcpTransport.prototype.name = "TcpTransport";

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
 * @returns {boolean} True if the objects have equal fields, false if not.
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
 * Connect to a TCP socket according to the info in connectionInfo. Listen on 
 * the port to read an entire packet element and call 
 * elementListener.onReceivedElement(element). Note: this connect method 
 * previously took a Face object which is deprecated and renamed as the method 
 * connectByFace.
 * @param {TcpTransport.ConnectionInfo} connectionInfo A
 * TcpTransport.ConnectionInfo with the host and port.
 * @param {an object with onReceivedElement} elementListener The elementListener 
 * must remain valid during the life of this object.
 * @param {function} onopenCallback Once connected, call onopenCallback().
 * @param {type} onclosedCallback If the connection is closed by the remote host, 
 * call onclosedCallback().
 * @returns {undefined}
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
        // Find the end of the packet element and call face.onReceivedElement.
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
