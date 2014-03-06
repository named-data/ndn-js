/** 
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Wentao Shang
 * See COPYING for copyright and distribution information.
 */

var DataUtils = require('../encoding/data-utils.js').DataUtils;
var ElementReader = require('../encoding/element-reader.js').ElementReader;
var LOG = require('../log.js').Log.LOG;

var TcpTransport = function TcpTransport() 
{    
  this.socket = null;
  this.sock_ready = false;
  this.elementReader = null;
  this.connectedHost = null; // Read by Face.
  this.connectedPort = null; // Read by Face.

  this.defaultGetHostAndPort = require('../face.js').Face.makeShuffledGetHostAndPort
    (["A.hub.ndn.ucla.edu", "B.hub.ndn.ucla.edu", "C.hub.ndn.ucla.edu", "D.hub.ndn.ucla.edu", 
      "E.hub.ndn.ucla.edu", "F.hub.ndn.ucla.edu", "G.hub.ndn.ucla.edu", "H.hub.ndn.ucla.edu", 
      "I.hub.ndn.ucla.edu", "J.hub.ndn.ucla.edu", "K.hub.ndn.ucla.edu"],
     6363);
};

exports.TcpTransport = TcpTransport;

TcpTransport.prototype.connect = function(face, onopenCallback) 
{
  if (this.socket != null)
    delete this.socket;

  this.elementReader = new ElementReader(face);

  // Connect to local ndnd via TCP
  var net = require('net');
  this.socket = new net.Socket();
    
  var self = this;

  this.socket.on('data', function(data) {      
    if (typeof data == 'object') {
      // Make a copy of data (maybe a Buffer or a String)
      var buf = new Buffer(data);
      try {
        // Find the end of the binary XML element and call face.onReceivedElement.
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
      
    // Close Face when TCP Socket is closed
    face.closeByTransport();
  });

  this.socket.connect({host: face.host, port: face.port});
  this.connectedHost = face.host;
  this.connectedPort = face.port;
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
