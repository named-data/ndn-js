/** 
 * @author: Wentao Shang
 * See COPYING for copyright and distribution information.
 */

var DataUtils = require('./encoding/DataUtils.js').DataUtils;
var BinaryXmlElementReader = require('./util/BinaryXMLElementReader.js').BinaryXmlElementReader;
var LOG = require('./Log.js').Log.LOG;

var TcpTransport = function TcpTransport() {    
  this.socket = null;
  this.sock_ready = false;
  this.elementReader = null;
  this.connectedHost = null; // Read by NDN.
  this.connectedPort = null; // Read by NDN.

  this.defaultGetHostAndPort = require('./NDN.js').NDN.makeShuffledGetHostAndPort
    (["A.hub.ndn.ucla.edu", "B.hub.ndn.ucla.edu", "C.hub.ndn.ucla.edu", "D.hub.ndn.ucla.edu", 
      "E.hub.ndn.ucla.edu", "F.hub.ndn.ucla.edu", "G.hub.ndn.ucla.edu", "H.hub.ndn.ucla.edu"],
     9695);
};

exports.TcpTransport = TcpTransport;

TcpTransport.prototype.connect = function(ndn, onopenCallback) {
  if (this.socket != null)
    delete this.socket;

  this.elementReader = new BinaryXmlElementReader(ndn);

  // Connect to local ndnd via TCP
  var net = require('net');
  this.socket = new net.Socket();
    
  var self = this;

  this.socket.on('data', function(data) {      
    if (typeof data == 'object') {
      // Make a copy of data (maybe a Buffer or a String)
      var buf = new Buffer(data);
      try {
        // Find the end of the binary XML element and call ndn.onReceivedElement.
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
      
    // Close NDN when TCP Socket is closed
    ndn.closeByTransport();
  });

  this.socket.connect({host: ndn.host, port: ndn.port});
  this.connectedHost = ndn.host;
  this.connectedPort = ndn.port;
};

/**
 * Send data.
 */
TcpTransport.prototype.send = function(/*Buffer*/ data) {
  if (this.sock_ready)
    this.socket.write(data);
  else
    console.log('TCP connection is not established.');
};

/**
 * Close transport
 */
TcpTransport.prototype.close = function () {
  this.socket.end();
  if (LOG > 3) console.log('TCP connection closed.');
};
