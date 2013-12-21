/*
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

var EXPORTED_SYMBOLS = [];

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cr = Components.results;

Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");
Components.utils.import("chrome://modules/content/ndn-js.jsm");
Components.utils.import("resource://gre/modules/NetUtil.jsm");

var FIB = [];
var PIT = [];

var PitEntry = function PitEntry(interest, face)
{
  this.interest = interest;
  this.face = face;
}

var ForwarderFace = function ForwarderFace(host, port, registeredPrefix)
{
  this.transport = new XpcomTransport();
  this.transport.connectHelper(host, port, this);
  // An HTTP request will be redirected to this.onHttpRequest.
  this.transport.setHttpListener(this);
  
  this.registeredPrefix = registeredPrefix;
};

ForwarderFace.prototype.onReceivedElement = function(element)
{
  var decoder = new BinaryXMLDecoder(element);
  // Dispatch according to packet type
  if (decoder.peekDTag(NDNProtocolDTags.Interest)) {
    var interest = new Interest();
    interest.from_ndnb(decoder);
    if (LOG > 3) dump("Interest packet received: " + interest.name.toUri() + "\n");
    
    // Add to the PIT.
    PIT.push(new PitEntry(interest, this));
    
    // Send the interest to the matching faces in the FIB.
    for (var i = 0; i < FIB.length; ++i) {
      var face = FIB[i];
      if (face == this)
        // Don't send the interest back to where it came from.
        continue;
      
      if (face.registeredPrefix != null && face.registeredPrefix.match(interest.name))
        face.transport.send(element);
    }
  } 
  else if (decoder.peekDTag(NDNProtocolDTags.Data)) { 
    var data = new Data();
    data.from_ndnb(decoder);
    if (LOG > 3) dump("Data packet received: " + data.name.toUri() + "\n");
    
    // Send the data packet to the face for each matching PIT entry.
    // Iterate backwards so we can remove the entry and keep iterating.
    for (var i = PIT.length - 1; i >= 0; --i) {
      if (PIT[i].interest.matchesName(data.name)) {
        if (LOG > 3) dump("Sending Data to match interest " + PIT[i].interest.name.toUri() + "\n");
        PIT[i].face.transport.send(element);
        
        // Remove this entry.
        PIT.splice(i, 1);
      }
    }
  }    
};

ForwarderFace.prototype.onHttpRequest = function(transport, request)
{
  // Remove the FIB entry with this transport since it is not NDN.
  for (var i = FIB.length - 1; i >= 0; --i) {
    if (FIB[i].transport == transport)
      FIB.splice(i, 1);
  }
  
  var response = "<html><title>NDN Forwarder</title><body>\r\n";
  
  response += "<h4>Faces</h4><ul>\r\n";
  for (var i = 0; i < FIB.length; ++i)
    response += "<li>" + FIB[i].transport.connectedHost + ":" + FIB[i].transport.connectedPort + 
      (FIB[i].registeredPrefix == null ? "" : " " + FIB[i].registeredPrefix.toUri()) + "</li>\r\n";
  response += "</ul>\r\n";        
          
  response += "\r\n</body></html>\r\n";
  
  transport.send(DataUtils.toNumbersFromString
    ("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\nContent-Length: " +
     response.length + "\r\n\r\n" + response));
};

var socketListener = {
  onSocketAccepted: function(aServer, socket) {
    if (LOG > 3) dump("Accepted connection from " + socket.host + ":" + socket.port + "\n");
    // TODO: Check if the FIB already has an entry for the same host and port?
    FIB.push(new ForwarderFace(socket));
  }
};

var serverSocket = Cc["@mozilla.org/network/server-socket;1"].createInstance(Ci.nsIServerSocket);
serverSocket.init(6363, true, -1);
serverSocket.asyncListen(socketListener);

// For now, hard code an initial forwarding connection.
FIB.push(new ForwarderFace("borges.metwi.ucla.edu", 9695, new Name("/ndn")));
