var readline = require('readline');
var Face = require('../..').Face;
var Name = require('../..').Name;

var onData = function(interest, data) {
  console.log("Got data packet with name " + data.name.toUri());
  console.log(data.content.toString('binary'));

  face.close();  // This will cause the script to quit.
};

var onTimeout = function(interest) {
  console.log("Time out for interest " + interest.name.toUri());
  face.close();  // This will cause the script to quit.
};

var face = new Face({host: "localhost"});

var rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

rl.question("Enter a word to echo: ", function(word) {
  var name = new Name("/testecho");
  name.append(word);
  console.log("Express name " + name.toUri());
  face.expressInterest(name, onData, onTimeout);

  rl.close();
});
