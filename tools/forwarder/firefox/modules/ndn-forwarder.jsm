/*
 * Copyright (C) 2013-2016 Regents of the University of California.
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

var ForwarderFace = function ForwarderFace
  (connectionInfoOrSocketTransport, registeredPrefix)
{
  this.transport = new XpcomTransport();
  this.transport.connectHelper(connectionInfoOrSocketTransport, this);
  // An HTTP request will be redirected to this.onHttpRequest.
  this.transport.setHttpListener(this);
  
  this.registeredPrefix = registeredPrefix;
};

ForwarderFace.prototype.onReceivedElement = function(element)
{
  if (LOG > 3) dump("Complete element received. Length " + element.length + "\n");
  // First, decode as Interest or Data.
  var interest = null;
  var data = null;
  if (element[0] == Tlv.Interest || element[0] == Tlv.Data) {
    var decoder = new TlvDecoder (element);
    if (decoder.peekType(Tlv.Interest, element.length)) {
      interest = new Interest();
      interest.wireDecode(element, TlvWireFormat.get());
    }
    else if (decoder.peekType(Tlv.Data, element.length)) {
      data = new Data();
      data.wireDecode(element, TlvWireFormat.get());
    }
  }

  // Now process as Interest or Data.
  if (interest !== null) {
    if (LOG > 3) dump("Interest packet received: " + interest.getName().toUri() + "\n");
    
    // Add to the PIT.
    PIT.push(new PitEntry(interest, this));
    
    // Send the interest to the matching faces in the FIB.
    for (var i = 0; i < FIB.length; ++i) {
      var face = FIB[i];
      if (face == this)
        // Don't send the interest back to where it came from.
        continue;
      
      if (face.registeredPrefix != null && face.registeredPrefix.match(interest.getName()))
        face.transport.send(element);
    }
  } 
  else if (data !== null) {
    if (LOG > 3) dump("Data packet received: " + data.getName().toUri() + "\n");
    
    // Send the data packet to the face for each matching PIT entry.
    // Iterate backwards so we can remove the entry and keep iterating.
    for (var i = PIT.length - 1; i >= 0; --i) {
      if (PIT[i].interest.matchesName(data.getName())) {
        if (LOG > 3) dump("Sending Data to match interest " + PIT[i].interest.getName().toUri() + "\n");
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
    response += "<li>" + FIB[i].transport.connectionInfo.host + ":" +
      FIB[i].transport.connectionInfo.port +
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
FIB.push(new ForwarderFace
  (new XpcomTransport.ConnectionInfo("memoria.ndn.ucla.edu", 6363), new Name("/")));
