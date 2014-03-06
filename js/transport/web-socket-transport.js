/** 
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Wentao Shang
 * See COPYING for copyright and distribution information.
 */

var ElementReader = require('../encoding/element-reader.js').ElementReader;
var LOG = require('../log.js').Log.LOG;

/**
 * @constructor
 */
var WebSocketTransport = function WebSocketTransport() 
{    
  if (!WebSocket)
    throw new Error("WebSocket support is not available on this platform.");
    
  this.ws = null;
  this.connectedHost = null; // Read by Face.
  this.connectedPort = null; // Read by Face.
  this.elementReader = null;
  this.defaultGetHostAndPort = Face.makeShuffledGetHostAndPort
    (["A.ws.ndn.ucla.edu", "B.ws.ndn.ucla.edu", "C.ws.ndn.ucla.edu", "D.ws.ndn.ucla.edu", 
      "E.ws.ndn.ucla.edu", "F.ws.ndn.ucla.edu", "G.ws.ndn.ucla.edu", "H.ws.ndn.ucla.edu", 
      "I.ws.ndn.ucla.edu", "J.ws.ndn.ucla.edu", "K.ws.ndn.ucla.edu", "L.ws.ndn.ucla.edu", 
      "M.ws.ndn.ucla.edu", "N.ws.ndn.ucla.edu"],
     9696);
};

exports.WebSocketTransport = WebSocketTransport;

/**
 * Connect to the host and port in face.  This replaces a previous connection and sets connectedHost
 *   and connectedPort.  Once connected, call onopenCallback().
 * Listen on the port to read an entire binary XML encoded element and call
 *    face.onReceivedElement(element).
 */
WebSocketTransport.prototype.connect = function(face, onopenCallback) 
{
  if (this.ws != null)
    delete this.ws;
  
  this.ws = new WebSocket('ws://' + face.host + ':' + face.port);
  if (LOG > 0) console.log('ws connection created.');
    this.connectedHost = face.host;
    this.connectedPort = face.port;
  
  this.ws.binaryType = "arraybuffer";
  
  this.elementReader = new ElementReader(face);
  var self = this;
  this.ws.onmessage = function(ev) {
    var result = ev.data;
    //console.log('RecvHandle called.');
      
    if (result == null || result == undefined || result == "") {
      console.log('INVALID ANSWER');
    } 
    else if (result instanceof ArrayBuffer) {
      var bytearray = new Buffer(result);
          
      if (LOG > 3) console.log('BINARY RESPONSE IS ' + bytearray.toString('hex'));
      
      try {
        // Find the end of the binary XML element and call face.onReceivedElement.
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
    
    // Close Face when WebSocket is closed
    face.readyStatus = Face.CLOSED;
    face.onclose();
    //console.log("NDN.onclose event fired.");
  }
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
