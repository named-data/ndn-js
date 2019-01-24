/**
 * Copyright (C) 2016-2019 Regents of the University of California.
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

/**
 * A MicroForwarder holds a PIT, FIB and faces to function as a simple NDN
 * forwarder.
 * Create a new MicroForwarder, using chrome.runtime.onConnect.addListener to
 * get the port and add a new face to use a RuntimePortTransport to communiate
 * with the WebExtensions port.
 */
var MicroForwarder = function MicroForwarder()
{
  this.PIT_ = [];   // of PitEntry
  this.FIB_ = [];   // of FibEntry
  this.faces_ = []; // of ForwarderFace
  this.CS_ = {};    // Key: The Data name URI. Value: The Data object.

  // Add a listener to wait for a connection request from a tab and add a face.
  var thisForwarder = this;
  chrome.runtime.onConnect.addListener(function(port) {
    thisForwarder.addFace
      ("internal://port", new RuntimePortTransport(),
       new RuntimePortTransport.ConnectionInfo(port));
  });

  // Use Native Messaging to connect to the ndn_multicast app to send and
  // receive to other computers on the LAN using the NDN multicast group.
  // Make a FIB entry to multicast all Interests.
  if (chrome.runtime.connectNative) {
    var port = chrome.runtime.connectNative("ndn_multicast");
    var faceId = this.addFace
      ("nativePort://ndn_multicast", new RuntimePortTransport(),
       new RuntimePortTransport.ConnectionInfo(port));
    this.registerRoute(new Name("/ndn"), faceId);
  }
};


/**
 * Add a new face to communicate with the given transport. This immediately
 * connects using the connectionInfo. If the transport connection is closed,
 * disable and remove the face.
 * @param {string} uri The URI to use in the faces/query and faces/list
 * commands.
 * @param {Transport} transport An object of a subclass of Transport to use
 * for communication. If the transport object has a "setOnReceivedObject"
 * method, then use it to set the onReceivedObject callback.
 * @param {TransportConnectionInfo} connectionInfo This must be a
 * ConnectionInfo from the same subclass of Transport as transport.
 * @return {number} The new face ID.
 */
MicroForwarder.prototype.addFace = function(uri, transport, connectionInfo)
{
  var face = null;
  var thisForwarder = this;
  if ("setOnReceivedObject" in transport)
    transport.setOnReceivedObject
      (function(obj) { thisForwarder.onReceivedObject(face, obj); });
  face = new ForwarderFace(uri, transport);

  function onClosedCallback() {
    face.disable();
    for (var i = 0; i < thisForwarder.faces_.length; ++i) {
      if (thisForwarder.faces_[i] === face) {
        // TODO: Mark this face as disconnected so the FIB doesn't use it.
        thisForwarder.faces_.splice(i, 1);
        break;
      }
    }
  }

  transport.connect
    (connectionInfo,
     { onReceivedElement: function(element) {
         thisForwarder.onReceivedElement(face, element); } },
     function(){}, onClosedCallback);
  this.faces_.push(face);

  return face.faceId;
};

/**
 * Find or create the FIB entry with the given name and add the ForwarderFace
 * with the given faceId.
 * @param {Name} name The name of the FIB entry.
 * @param {number} faceId The face ID of the face for the route.
 * @return {boolean} True for success, or false if can't find the ForwarderFace
 * with faceId.
 */
MicroForwarder.prototype.registerRoute = function(name, faceId)
{
  // Find the face with the faceId.
  var nexthopFace = null;
  for (var i = 0; i < this.faces_.length; ++i) {
    if (this.faces_[i].faceId == faceId) {
      nexthopFace = this.faces_[i];
      break;
    }
  }

  if (nexthopFace == null)
    return false;

  // Check for a FIB entry for the name and add the face.
  for (var i = 0; i < this.FIB_.length; ++i) {
    var fibEntry = this.FIB_[i];
    if (fibEntry.name.equals(name)) {
      // Make sure the face is not already added.
      if (fibEntry.faces.indexOf(nexthopFace) < 0)
        fibEntry.faces.push(nexthopFace);

      return true;
    }
  }

  // Make a new FIB entry.
  var fibEntry = new FibEntry(name);
  fibEntry.faces.push(nexthopFace);
  this.FIB_.push(fibEntry);

  return true;
}

/**
 * This is called by the listener when an entire TLV element is received.
 * If it is an Interest, look in the FIB for forwarding. If it is a Data packet,
 * look in the PIT to match an Interest.
 * @param {ForwarderFace} face The ForwarderFace with the transport that
 * received the element.
 * @param {Buffer} element The received element.
 */
MicroForwarder.prototype.onReceivedElement = function(face, element)
{
  if (LOG > 3) console.log("Complete element received. Length " + element.length + "\n");
  // First, decode as Interest or Data.
  var interest = null;
  var data = null;
  if (element[0] == Tlv.Interest || element[0] == Tlv.Data) {
    var decoder = new TlvDecoder(element);
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
    var interestUri = interest.getName().toUri();
    if (LOG > 3) console.log("Interest packet received: " + interestUri + "\n");
    if (MicroForwarder.localhostNamePrefix.match(interest.getName())) {
      this.onReceivedLocalhostInterest(face, interest);
      return;
    }

    // Check CS.
    // TODO: This uses exact name match. Should match on prefix and use selectors.
    if (interestUri in this.CS_) {
      if (LOG > 3) console.log("Data found in CS: " + interestUri + "\n");
      face.sendBuffer(this.CS_[interestUri].wireEncode().buf());
      return;
    }

    for (var i = 0; i < this.PIT_.length; ++i) {
      // TODO: Check interest equality of appropriate selectors.
      if (this.PIT_[i].face == face &&
          this.PIT_[i].interest.getName().equals(interest.getName())) {
        // Duplicate PIT entry.
        // TODO: Update the interest timeout?
        if (LOG > 3) console.log("Duplicate Interest: " + interest.getName().toUri());
        return;
      }
    }

    // Add to the PIT.
    var pitEntry = new PitEntry(interest, face);
    this.PIT_.push(pitEntry);
    // Set the interest timeout timer.
    var thisForwarder = this;
    var timeoutCallback = function() {
      if (LOG > 3) console.log("Interest time out: " + interest.getName().toUri() + "\n");
      // Remove the face's entry from the PIT
      var index = thisForwarder.PIT_.indexOf(pitEntry);
      if (index >= 0)
        thisForwarder.PIT_.splice(index, 1);
    };
    var timeoutMilliseconds = (interest.getInterestLifetimeMilliseconds() || 4000);
    pitEntry.timerId_ = setTimeout(timeoutCallback, timeoutMilliseconds);

    if (MicroForwarder.broadcastNamePrefix.match(interest.getName())) {
      // Special case: broadcast to all faces.
      for (var i = 0; i < this.faces_.length; ++i) {
        var outFace = this.faces_[i];
        // Don't send the interest back to where it came from.
        if (outFace != face)
          outFace.sendBuffer(element);
      }
    }
    else {
      // Send the interest to the faces in matching FIB entries.
      for (var i = 0; i < this.FIB_.length; ++i) {
        var fibEntry = this.FIB_[i];

        // TODO: Need to do longest prefix match?
        if (fibEntry.name.match(interest.getName())) {
          for (var j = 0; j < fibEntry.faces.length; ++j) {
            var outFace = fibEntry.faces[j];
            // Don't send the interest back to where it came from.
            if (outFace != face)
              outFace.sendBuffer(element);
          }
        }
      }
    }
  }
  else if (data !== null) {
    if (LOG > 3) console.log("Data packet received: " + data.getName().toUri() + "\n");

    //insert into CS
    if (LOG > 3) console.log("Insert Data in CS" + data.getName().toUri() + "\n");
    this.CS_[data.getName().toUri()] = data;

    // Send the data packet to the face for each matching PIT entry.
    // Iterate backwards so we can remove the entry and keep iterating.
    for (var i = this.PIT_.length - 1; i >= 0; --i) {
      var entry = this.PIT_[i];
      if (entry.face != face && entry.face != null &&
          entry.interest.matchesData(data)) {
        // Clear the timeout.
        clearTimeout(entry.timerId_);
        entry.timerId_ = -1;

        // Remove the entry before sending.
        this.PIT_.splice(i, 1);

        if (LOG > 3) console.log("Sending Data to match interest " + entry.interest.getName().toUri() + "\n");
        entry.face.sendBuffer(element);
        entry.face = null;
      }
    }
  }
};

/**
 * Process a received interest if it begins with /localhost.
 * @param {ForwarderFace} face The ForwarderFace with the transport that
 * received the interest.
 * @param {Interest} interest The received interest.
 */
MicroForwarder.prototype.onReceivedLocalhostInterest = function(face, interest)
{
  if (MicroForwarder.registerNamePrefix.match(interest.getName())) {
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

    if (!this.registerRoute(controlParameters.getName(), face.faceId))
      // TODO: Send error reply?
      return;

    // Send the ControlResponse.
    var controlResponse = new ControlResponse();
    controlResponse.setStatusText("Success");
    controlResponse.setStatusCode(200);
    controlResponse.setBodyAsControlParameters(controlParameters);
    var responseData = new Data(interest.getName());
    responseData.setContent(controlResponse.wireEncode());
    // TODO: Sign the responseData.
    face.sendBuffer(responseData.wireEncode().buf());
  }
  else {
    if (LOG > 3) console.log("Unrecognized localhost prefix " + interest.getName() + "\n");
  }
};

/**
 * This is called when a JavaScript object is received on a local face.
 * @param {ForwarderFace} face The ForwarderFace with the transport that
 * received the object.
 * @param {object} obj The JavaScript object.
 */
MicroForwarder.prototype.onReceivedObject = function(face, obj)
{
  if (obj.type == "fib/list") {
    obj.fib = [];
    for (var i = 0; i < this.FIB_.length; ++i) {
      var fibEntry = this.FIB_[i];

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

    face.sendObject(obj);
  }
  else if (obj.type == "faces/list") {
    obj.faces = [];
    for (var i = 0; i < this.faces_.length; ++i) {
      obj.faces.push({
        faceId: this.faces_[i].faceId,
        uri: this.faces_[i].uri
      });
    }

    face.sendObject(obj);
  }
  else if (obj.type == "faces/query") {
    for (var i = 0; i < this.faces_.length; ++i) {
      if (this.faces_[i].uri == obj.uri) {
        // We found the desired face.
        obj.faceId = this.faces_[i].faceId;
        break;
      }
    }
    face.sendObject(obj);
  }
  else if (obj.type == "faces/create") {
    // TODO: Re-check that the face doesn't exist.
    var sentReply = false;
    var newFace = null;

    var thisForwarder = this;
    // Some transports can't report a connection failure, so use a timeout.
    var timerId = setTimeout(function() {
      // A problem opening the WebSocket.
      // Only reply once.
      if (sentReply)
        return;
      sentReply = true;

      obj.statusCode = 503;
      face.sendObject(obj);
    }, 3000);
    function onConnected() {
      if (sentReply)
        // Only reply once.
        return;
      sentReply = true;

      // Cancel the timeout timer.
      clearTimeout(timerId);
      thisForwarder.faces_.push(newFace);
      obj.faceId = newFace.faceId;
      obj.statusCode = 200;
      face.sendObject(obj);
    }

    var transport = new WebSocketTransport();
    newFace = new ForwarderFace(obj.uri, transport);
    transport.connect
      (new WebSocketTransport.ConnectionInfo(obj.uri),
      { onReceivedElement: function(element) {
          thisForwarder.onReceivedElement(newFace, element); } },
      onConnected);
  }
  else if (obj.type == "rib/register") {
    var faceId;
    if (obj.faceId != null)
      faceId = obj.faceId;
    else
      // Use the requesting face.
      faceId = face.faceId;

    if (!this.registerRoute(new Name(obj.nameUri), faceId))
      // TODO: Send error reply?
      return;

    obj.statusCode = 200;
    face.sendObject(obj);
  }
};

MicroForwarder.localhostNamePrefix = new Name("/localhost");
MicroForwarder.registerNamePrefix = new Name("/localhost/nfd/rib/register");
MicroForwarder.broadcastNamePrefix = new Name("/ndn/broadcast");

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
 * A ForwarderFace is used by the faces list to represent a connection using the
 * given Transport.
 * Create a new ForwarderFace and set the faceId to a unique value.
 * @param {string} uri The URI to use in the faces/query and faces/list
 * commands.
 * @param {Transport} transport Communicate using the Transport object. You must
 * call transport.connect with an elementListener object whose
 * onReceivedElement(element) calls
 * microForwarder.onReceivedElement(face, element), with this face. If available
 * the transport's onReceivedObject(obj) should call
 * microForwarder.onReceivedObject(face, obj), with this face.
 * @constructor
 */
var ForwarderFace = function ForwarderFace(uri, transport)
{
  this.uri = uri;
  this.transport = transport;
  this.faceId = ++ForwarderFace.lastFaceId;
};

ForwarderFace.lastFaceId = 0;

/**
 * Check if this face is still enabled.
 * @return {boolean} True if this face is still enabled.
 */
ForwarderFace.prototype.isEnabled = function()
{
  return this.transport != null;
};

/**
 * Disable this face so that isEnabled() returns false.
 */
ForwarderFace.prototype.disable = function() { this.transport = null; };

/**
 * Send the object to the transport, if this face is still enabled.
 * @param {object} obj The object to send.
 */
ForwarderFace.prototype.sendObject = function(obj)
{
  if (this.transport != null && this.transport.sendObject != null)
    this.transport.sendObject(obj);
};

/**
 * Send the buffer to the transport, if this face is still enabled.
 * @param {Buffer} buffer The bytes to send.
 */
ForwarderFace.prototype.sendBuffer = function(buffer)
{
  if (this.transport != null)
    this.transport.send(buffer);
};

// Create the only instance and start listening on the WebExtensions port.
var microForwarder = new MicroForwarder();
