var NDN = require('../..').NDN;
var Name = require('../..').Name;
var Interest = require('../..').Interest;
var Closure = require('../..').Closure;
var EncodingUtils = require('../..').EncodingUtils;

var onData = function (inst, data) {
    console.log("Data received in callback.");
    console.log('Name: ' + data.name.toUri());
    console.log('Content: ' + data.content.toString());
    console.log(EncodingUtils.dataToHtml(data).replace(/<br \/>/g, "\n"));
    
    console.log('Quit script now.');
    ndn.close();  // This will cause the script to quit
};

var onTimeout = function (interest) {
    console.log("Interest time out.");
    console.log('Interest name: ' + interest.name.toUri());
    console.log('Quit script now.');
    ndn.close();
};

/**
 * A WrapperClosure wraps the callback functions in a Closure.  When expressInterest is changed to
 * use the callback functions directly, we don't need this anymore.
 */
var WrapperClosure = function WrapperClosure(onData, onTimeout) {
  // Inherit from Closure.
  Closure.call(this);
  
  this.onData = onData;
  this.onTimeout = onTimeout;
};
    
WrapperClosure.prototype.upcall = function(kind, upcallInfo) {
  if (kind == Closure.UPCALL_CONTENT || kind == Closure.UPCALL_CONTENT_UNVERIFIED)
    this.onData(upcallInfo.interest, upcallInfo.data);
  else if (kind == Closure.UPCALL_INTEREST_TIMED_OUT)
    this.onTimeout(upcallInfo.interest);

  return Closure.RESULT_OK;
};

var ndn = new NDN();
var name = new Name('/');
var template = new Interest();
template.answerOriginKind = Interest.ANSWER_NO_CONTENT_STORE;  // bypass cache in ccnd
template.interestLifetime = 4000;
ndn.expressInterest(name, new WrapperClosure(onData, onTimeout), template);
console.log('Interest expressed.');
