var FIB = [];
var PIT = [];

// Add a listener to wait for connection request from tab
chrome.runtime.onConnect.addListener(function(port) {
  FIB.push(new ForwarderFace(port));
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
 * A ForwarderFace is used by the FIB to represent a connection using a
 * runtime.Port.
 * @param {runtime.Port} port
 * @constructor
 */
var ForwarderFace = function ForwarderFace(port)
{
  this.port = port;
  this.registeredPrefixes = [];
  this.elementReader = new ElementReader(this);

	// Add a listener to wait for msg from the tab
  var thisFace = this;
	this.port.onMessage.addListener(function(buffer) {
		thisFace.elementReader.onReceivedData(buffer);
	});
};

/**
 * This is called by the port listener when an entire TLV element is received.
 * If it is an Interest, look in the FIB for forwarding. If it is a Data packet,
 * look in the PIT to match an Interest.
 * @param {Buffer} element
 */
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
    if (ForwarderFace.localhostNamePrefix.match(interest.getName())) {
      this.onReceivedLocalhostInterest(interest);
      return;
    }

    for (var i = 0; i < PIT.length; ++i) {
      // TODO: Check interest equality of appropriate selectors.
      if (PIT[i].face == this &&
          PIT[i].interest.getName().equals(interest.getName()))
        // Duplicate PIT entry.
        // TODO: Update the interest timeout?
        return;
    }

    // Add to the PIT.
    var pitEntry = new PitEntry(interest, this);
    PIT.push(pitEntry);
    // Set the interest timeout timer.
    var timeoutCallback = function() {
      if (LOG > 3) dump("Interest time out: " + interest.getName().toUri() + "\n");
      // Remove this entry from the PIT
      var index = PIT.indexOf(pitEntry);
      if (index >= 0)
        PIT.splice(index, 1);
    };
    var timeoutMilliseconds = (interest.getInterestLifetimeMilliseconds() || 4000);
    setTimeout(timeoutCallback, timeoutMilliseconds);

    // Send the interest to the matching faces in the FIB.
    for (var i = 0; i < FIB.length; ++i) {
      var face = FIB[i];
      if (face == this)
        // Don't send the interest back to where it came from.
        continue;

      if (ForwarderFace.broadcastNamePrefix.match(interest.getName())) {
        face.port.postMessage(element);
        continue;
      }

      for (var j = 0; j < face.registeredPrefixes.length; ++j) {
        var registeredPrefix = face.registeredPrefixes[j];

        if (registeredPrefix.match(interest.getName()))
          face.port.postMessage(element);
      }
    }
  }
  else if (data !== null) {
    if (LOG > 3) dump("Data packet received: " + data.getName().toUri() + "\n");

    // Send the data packet to the face for each matching PIT entry.
    // Iterate backwards so we can remove the entry and keep iterating.
    for (var i = PIT.length - 1; i >= 0; --i) {
      if (PIT[i].interest.matchesName(data.getName())) {
        if (LOG > 3) dump("Sending Data to match interest " + PIT[i].interest.getName().toUri() + "\n");
        PIT[i].face.port.postMessage(element);

        // Remove this entry.
        PIT.splice(i, 1);
      }
    }
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
      if (LOG > 3) dump("Error decoding register interest ControlParameters " + ex + "\n");
      return;
    }
    // TODO: Verify the signature?

    if (LOG > 3) dump("Received register request " + controlParameters.getName().toUri() + "\n");
    this.registeredPrefixes.push(controlParameters.getName());

    // Send the ControlResponse.
    var controlResponse = new ControlResponse();
    controlResponse.setStatusText("Success");
    controlResponse.setStatusCode(200);
    controlResponse.setBodyAsControlParameters(controlParameters);
    var responseData = new Data(interest.getName());
    responseData.setContent(controlResponse.wireEncode());
    // TODO: Sign the responseData.
    this.port.postMessage(responseData.wireEncode().buf());
  }
  else {
    if (LOG > 3) dump("Unrecognized localhost prefix " + interest.getName() + "\n");
  }
};

ForwarderFace.localhostNamePrefix = new Name("/localhost");
ForwarderFace.registerNamePrefix = new Name("/localhost/nfd/rib/register");
ForwarderFace.broadcastNamePrefix = new Name("/ndn/broadcast");
