/*
 * Copyright (C) 2014 Regents of the University of California.
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

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
