var Face = require('../..').Face;
var Name = require('../..').Name;
var Interest = require('../..').Interest;
var Data = require('../..').Data;
var SignedInfo = require('../..').SignedInfo;
var Closure = require('../..').Closure;

function onInterest(prefix, interest, transport) {
  console.log("Interest received : " + interest.name.toUri());

  // Make and sign a Data packet.
  var contentString = "Echo " + interest.name.toUri();
  var data = new Data(interest.name, new SignedInfo(), new Buffer(contentString));
  data.signedInfo.setFields();
  data.sign();
  var encodedData = data.encode();

  try {
    console.log("Send content " + contentString);
    transport.send(encodedData);
  } catch (e) {
    console.log(e.toString());
  }
}

function onRegisterFailed(prefix) 
{
  console.log("Register failed for prefix " + prefix.toUri());
  face.close();  // This will cause the script to quit.
}

var AsyncPutClosure = function AsyncPutClosure() {
  // Inherit from Closure.
  Closure.call(this);
};

AsyncPutClosure.prototype.upcall = function(kind, upcallInfo) {
  if (kind == Closure.UPCALL_INTEREST)
    onInterest(null, upcallInfo.interest, face.transport);

  return Closure.RESULT_OK;
};

var face = new Face({host: "localhost"});

face.registerPrefix(new Name("/testecho"), new AsyncPutClosure());
console.log("Started...");
