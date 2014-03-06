/** 
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 * Implement getAsync and putAsync used by Face using nsISocketTransportService.
 * This is used inside Firefox XPCOM modules.
 */

// Assume already imported the following:
// Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");
// Components.utils.import("resource://gre/modules/NetUtil.jsm");

/**
 * @constructor
 */
var XpcomTransport = function XpcomTransport() 
{
  this.elementListener = null;
  this.socket = null; // nsISocketTransport
  this.outStream = null;
  this.connectedHost = null; // Read by Face.
  this.connectedPort = null; // Read by Face.
  this.httpListener = null;

  this.defaultGetHostAndPort = Face.makeShuffledGetHostAndPort
    (["A.hub.ndn.ucla.edu", "B.hub.ndn.ucla.edu", "C.hub.ndn.ucla.edu", "D.hub.ndn.ucla.edu", 
      "E.hub.ndn.ucla.edu", "F.hub.ndn.ucla.edu", "G.hub.ndn.ucla.edu", "H.hub.ndn.ucla.edu", 
      "I.hub.ndn.ucla.edu", "J.hub.ndn.ucla.edu", "K.hub.ndn.ucla.edu"],
     6363);
};

/**
 * Connect to the host and port in face.  This replaces a previous connection and sets connectedHost
 *   and connectedPort.  Once connected, call onopenCallback().
 * Listen on the port to read an entire binary XML encoded element and call
 *    face.onReceivedElement(element).
 */
XpcomTransport.prototype.connect = function(face, onopenCallback) 
{
  this.elementListener = face;
  this.connectHelper(face.host, face.port, face);

  onopenCallback();
};

/**
 * Do the work to connect to the socket.  This replaces a previous connection and sets connectedHost
 *   and connectedPort.
 * @param {string|object} host The host to connect to. However, if host is not a string, assume it is an
 * nsISocketTransport which is already configured for a host and port, in which case ignore port and set 
 * connectedHost and connectedPort to host.host and host.port .
 * @param {number} port The port number to connect to.  If host is an nsISocketTransport then this is ignored.
 * @param {object} elementListener Listen on the port to read an entire binary XML encoded element and call
 *    elementListener.onReceivedElement(element).
 */
XpcomTransport.prototype.connectHelper = function(host, port, elementListener) 
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
  if (typeof host == 'string') {
    var transportService = Components.classes["@mozilla.org/network/socket-transport-service;1"].getService
          (Components.interfaces.nsISocketTransportService);
    this.socket = transportService.createTransport(null, 0, host, port, null);
    if (LOG > 0) console.log('XpcomTransport: Connected to ' + host + ":" + port);
    this.connectedHost = host;
    this.connectedPort = port;
  }
  else if (typeof host == 'object') {
    // Assume host is an nsISocketTransport which is already configured for a host and port.
    this.socket = host;
    this.connectedHost = this.socket.host;
    this.connectedPort = this.socket.port;
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
  if (this.socket == null || this.connectedHost == null || this.connectedPort == null) {
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
      console.log("XpcomTransport.send: Trying to reconnect to " + this.connectedHost + ":" + 
                  this.connectedPort + " and resend after exception: " + ex);

    this.connectHelper(this.connectedHost, this.connectedPort, this.elementListener);
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
