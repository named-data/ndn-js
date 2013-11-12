var Face = require('../..').Face;
var Name = require('../..').Name;
var Interest = require('../..').Interest;
var Closure = require('../..').Closure;
var EncodingUtils = require('../..').EncodingUtils;

var onData = function(interest, data) {
  console.log("Data received in callback.");
  console.log('Name: ' + data.name.toUri());
  console.log('Content: ' + data.content.toString());
  console.log(EncodingUtils.dataToHtml(data).replace(/<br \/>/g, "\n"));

  console.log('Quit script now.');
  face.close();  // This will cause the script to quit.
};

var onTimeout = function(interest) {
  console.log("Interest time out.");
  console.log('Interest name: ' + interest.name.toUri());
  console.log('Quit script now.');
  face.close();  // This will cause the script to quit.
};

var face = new Face();
var name = new Name('/');
var template = new Interest();
template.interestLifetime = 4000;
face.expressInterest(name, template, onData, onTimeout);
console.log('Interest expressed.');
