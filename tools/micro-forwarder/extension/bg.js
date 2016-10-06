/**
 * Copyright (C) 2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
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

var PIT = [];   // of PitEntry
var FIB = [];   // of FibEntry
var Faces = []; // of ForwarderFace

// Add a listener to wait for a connection request from a tab.
chrome.runtime.onConnect.addListener(function(port) {
  Faces.push(new ForwarderFace("internal://port", port));
});

/**
 * A PitEntry is used in the PIT to record the face on which an Interest came in.
 * @param {Interest} interest
 * @param {ForwarderFace} face
 * @constructor
 */
var PitEntry = function PitEntry(interest, face)
{
  this.interest = interest;
  this.face = face;
};

/**
 * A FibEntry is used in the FIB to match a registered name with related faces.
 * @param {Name} name The registered name for this FIB entry.
 * @constructor
 */
var FibEntry = function FibEntry(name)
{
  this.name = name;
  this.faces = []; // of ForwarderFace
};

/**
 * A ForwarderFace is used by the Faces list to represent a connection using a
 * runtime.Port or a WebSocket.
 * @param {string} The URI to use in the faces/query and faces/list commands.
 * @param {runtime.Port} port If supplied, communicate with the port. Otherwise
 * if this is null then use webSocket.
 * @param {WebSocket} webSocket If a port is not supplied, communicate using the
 * WebSocket object which is already created with the host name.
 * @param {function} onComplete (optional) When the operation is complete,
 * this calls onComplete(success) where success is true if the face is created
 * or false if the face cannot be completed. If onComplete is omitted, this does
 * not call it. (This is mainly to get the result of opening a WebSocket but is
 * also called for a port.)
 * @constructor
 */
var ForwarderFace = function ForwarderFace(uri, port, webSocket, onComplete)
{
  this.uri = uri;
  this.port = port;
  this.webSocket = webSocket;
  this.elementReader = new ElementReader(this);
  this.faceId = ++ForwarderFace.lastFaceId;

  var thisFace = this;
  if (port != null) {
    // Add a listener to wait for a message object from the tab
    this.port.onMessage.addListener(function(obj) {
      if (obj.type == "Buffer")
        thisFace.elementReader.onReceivedData(new Buffer(obj.data));
      else
        thisFace.onReceivedObject(obj);
    });

    this.port.onDisconnect.addListener(function() {
      for (var i = 0; i < Faces.length; ++i) {
        if (Faces[i] === thisFace) {
          // TODO: Mark this face as disconnected so the FIB doesn't use it.
          Faces.splice(i, 1);
          break;
        }
      }
      thisFace.port = null;
    });

    if (onComplete)
      onComplete(true);
  }
  else {
    this.webSocket.binaryType = "arraybuffer";

    var thisFace = this;
    this.webSocket.onmessage = function(ev) {
      var result = ev.data;

      if (result == null || result == undefined || result == "")
        console.log('INVALID ANSWER');
      else if (result instanceof ArrayBuffer) {
        // The Buffer constructor expects an instantiated array.
        var bytearray = new Buffer(new Uint8Array(result));

        if (LOG > 3) console.log('BINARY RESPONSE IS ' + bytearray.toString('hex'));

        try {
          // Find the end of the element and call onReceivedElement.
          thisFace.elementReader.onReceivedData(bytearray);
        } catch (ex) {
          console.log("NDN.webSocket.onmessage exception: " + ex);
          return;
        }
      }
    };

    // Make sure we only call onComplete once.
    var calledOnComplete = false;
    this.webSocket.onopen = function(ev) {
      if (LOG > 3) console.log(ev);
      if (LOG > 3) console.log('webSocket.onopen: WebSocket connection opened.');
      if (onComplete && !calledOnComplete) {
        calledOnComplete = true;
        onComplete(true);
      }
    };

    this.webSocket.onerror = function(ev) {
      console.log(ev);
      console.log('webSocket.onerror: WebSocket error: ' + ev.data);
      if (onComplete && !calledOnComplete) {
        calledOnComplete = true;
        onComplete(false);
      }
    };

    this.webSocket.onclose = function(ev) {
      console.log('webSocket.onclose: WebSocket connection closed.');
      thisFace.webSocket = null;
    };
  }
};

ForwarderFace.lastFaceId = 0;

/**
 * This is called by the port listener when an entire TLV element is received.
 * If it is an Interest, look in the FIB for forwarding. If it is a Data packet,
 * look in the PIT to match an Interest.
 * @param {Buffer} element
 */
ForwarderFace.prototype.onReceivedElement = function(element)
{
  if (LOG > 3) console.log("Complete element received. Length " + element.length + "\n");
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
    if (LOG > 3) console.log("Interest packet received: " + interest.getName().toUri() + "\n");
    if (ForwarderFace.localhostNamePrefix.match(interest.getName())) {
      this.onReceivedLocalhostInterest(interest);
      return;
    }

    for (var i = 0; i < PIT.length; ++i) {
      // TODO: Check interest equality of appropriate selectors.
      if (PIT[i].face == this &&
          PIT[i].interest.getName().equals(interest.getName())) {
        // Duplicate PIT entry.
        // TODO: Update the interest timeout?
        if (LOG > 3) console.log("Duplicate Interest: " + interest.getName().toUri());
          return;
      }
    }

    // Add to the PIT.
    var pitEntry = new PitEntry(interest, this);
    PIT.push(pitEntry);
    // Set the interest timeout timer.
    var timeoutCallback = function() {
      if (LOG > 3) console.log("Interest time out: " + interest.getName().toUri() + "\n");
      // Remove this entry from the PIT
      var index = PIT.indexOf(pitEntry);
      if (index >= 0)
        PIT.splice(index, 1);
    };
    var timeoutMilliseconds = (interest.getInterestLifetimeMilliseconds() || 4000);
    setTimeout(timeoutCallback, timeoutMilliseconds);

    if (ForwarderFace.broadcastNamePrefix.match(interest.getName())) {
      // Special case: broadcast to all faces.
      for (var i = 0; i < Faces.length; ++i) {
        var face = Faces[i];
        // Don't send the interest back to where it came from.
        if (face != this)
          face.sendBuffer(element);
      }
    }
    else {
      // Send the interest to the faces in matching FIB entries.
      for (var i = 0; i < FIB.length; ++i) {
        var fibEntry = FIB[i];

        // TODO: Need to do longest prefix match?
        if (fibEntry.name.match(interest.getName())) {
          for (var j = 0; j < fibEntry.faces.length; ++j) {
            var face = fibEntry.faces[j];
            // Don't send the interest back to where it came from.
            if (face != this)
              face.sendBuffer(element);
          }
        }
      }
    }
  }
  else if (data !== null) {
    if (LOG > 3) console.log("Data packet received: " + data.getName().toUri() + "\n");

    // Send the data packet to the face for each matching PIT entry.
    // Iterate backwards so we can remove the entry and keep iterating.
    for (var i = PIT.length - 1; i >= 0; --i) {
      if (PIT[i].face != this && PIT[i].face != null &&
          PIT[i].interest.matchesName(data.getName())) {
        if (LOG > 3) console.log("Sending Data to match interest " + PIT[i].interest.getName().toUri() + "\n");
        PIT[i].face.sendBuffer(element);
        PIT[i].face = null;

        // Remove this entry.
        PIT.splice(i, 1);
      }
    }
  }
};

ForwarderFace.prototype.isEnabled = function()
{
  return this.port != null || this.webSocket != null;
};

ForwarderFace.prototype.sendObject = function(obj)
{
  if (this.port == null)
    return;
  this.port.postMessage(obj);
};

/**
 * Send the buffer to the port or WebSocket.
 * @param {Buffer} buffer The bytes to send.
 */
ForwarderFace.prototype.sendBuffer = function(buffer)
{
  if (this.port != null)
    this.sendObject(buffer.toJSON());
  else if (this.webSocket != null) {
    // If we directly use data.buffer to feed ws.send(),
    // WebSocket may end up sending a packet with 10000 bytes of data.
    // That is, WebSocket will flush the entire buffer
    // regardless of the offset of the Uint8Array. So we have to create
    // a new Uint8Array buffer with just the right size and copy the
    // content from binaryInterest to the new buffer.
    //    ---Wentao
    var bytearray = new Uint8Array(buffer.length);
    bytearray.set(buffer);
    this.webSocket.send(bytearray.buffer);
  }
};

/**
 * Process a received interest if it begins with /localhost.
 * @param {Interest} interest The received interest.
 */
ForwarderFace.prototype.onReceivedLocalhostInterest = function(interest)
{
  if (ForwarderFace.registerNamePrefix.match(interest.getName())) {
    // Decode the ControlParameters.
    var controlParameters = new ControlParameters();
    try {
      controlParameters.wireDecode(interest.getName().get(4).getValue());
    } catch (ex) {
      if (LOG > 3) console.log("Error decoding register interest ControlParameters " + ex + "\n");
      return;
    }
    // TODO: Verify the signature?

    if (LOG > 3) console.log("Received register request " + controlParameters.getName().toUri() + "\n");

    var name = controlParameters.getName();
    // Check for a FIB entry for the name and add this face.
    var foundFibEntry = false;
    for (var i = 0; i < FIB.length; ++i) {
      var fibEntry = FIB[i];
      if (fibEntry.name.equals(name)) {
        // Make sure the face is not already added.
        if (fibEntry.faces.indexOf(this) < 0)
          fibEntry.faces.push(this);

        foundFibEntry = true;
        break;
      }
    }

    if (!foundFibEntry) {
      // Make a new FIB entry.
      var fibEntry = new FibEntry(name);
      fibEntry.faces.push(this);
      FIB.push(fibEntry);
    }

    // Send the ControlResponse.
    var controlResponse = new ControlResponse();
    controlResponse.setStatusText("Success");
    controlResponse.setStatusCode(200);
    controlResponse.setBodyAsControlParameters(controlParameters);
    var responseData = new Data(interest.getName());
    responseData.setContent(controlResponse.wireEncode());
    // TODO: Sign the responseData.
    this.sendBuffer(responseData.wireEncode().buf());
  }
  else {
    if (LOG > 3) console.log("Unrecognized localhost prefix " + interest.getName() + "\n");
  }
};

ForwarderFace.prototype.onReceivedObject = function(obj)
{
  if (obj.type == "fib/list") {
    obj.fib = [];
    for (var i = 0; i < FIB.length; ++i) {
      var fibEntry = FIB[i];

      var entry = { name: fibEntry.name.toUri(),
                    nextHops: [] };
      for (var j = 0; j < fibEntry.faces.length; ++j) {
        // Don't show disabled faces, e.g. for a closed browser tab.
        if (fibEntry.faces[j].isEnabled())
          entry.nextHops.push({ faceId: fibEntry.faces[j].faceId });
      }
      if (entry.nextHops.length > 0)
        obj.fib.push(entry);
    }

    this.sendObject(obj);
  }
  else if (obj.type == "faces/list") {
    obj.faces = [];
    for (var i = 0; i < Faces.length; ++i) {
      obj.faces.push({
        faceId: Faces[i].faceId,
        uri: Faces[i].uri
      });
    }

    this.sendObject(obj);
  }
  else if (obj.type == "faces/query") {
    for (var i = 0; i < Faces.length; ++i) {
      if (Faces[i].uri == obj.uri) {
        // We found the desired face.
        obj.faceId = Faces[i].faceId;
        break;
      }
    }
    this.sendObject(obj);
  }
  else if (obj.type == "faces/create") {
    // TODO: Re-check that the face doesn't exist.
    var thisFace = this;
    var face = new ForwarderFace(obj.uri, null, new WebSocket(obj.uri), function(success) {
      if (success) {
        Faces.push(face);
        obj.faceId = face.faceId;
        obj.statusCode = 200;
      }
      else
        // A problem opening the WebSocket.
        obj.statusCode = 503;

      thisFace.sendObject(obj);
    });
  }
  else if (obj.type == "rib/register") {
    // Find the face with the faceId.
    var face = null;
    for (var i = 0; i < Faces.length; ++i) {
      if (Faces[i].faceId == obj.faceId) {
        face = Faces[i];
        break;
      }
    }

    if (face == null) {
      // TODO: Send error reply.
      return;
    }

    var name = new Name(obj.nameUri);
    // Check for a FIB entry for the name and add the face.
    var foundFibEntry = false;
    for (var i = 0; i < FIB.length; ++i) {
      var fibEntry = FIB[i];
      if (fibEntry.name.equals(name)) {
        // Make sure the face is not already added.
        if (fibEntry.faces.indexOf(face) < 0)
          fibEntry.faces.push(face);

        foundFibEntry = true;
        break;
      }
    }

    if (!foundFibEntry) {
      // Make a new FIB entry.
      var fibEntry = new FibEntry(name);
      fibEntry.faces.push(face);
      FIB.push(fibEntry);
    }

    obj.statusCode = 200;
    this.sendObject(obj);
  }
};

ForwarderFace.localhostNamePrefix = new Name("/localhost");
ForwarderFace.registerNamePrefix = new Name("/localhost/nfd/rib/register");
ForwarderFace.broadcastNamePrefix = new Name("/ndn/broadcast");
