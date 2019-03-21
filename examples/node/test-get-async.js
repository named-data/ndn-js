/*
 * Copyright (C) 2018-2019 Regents of the University of California.
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

var Face = require('../..').Face;
var Name = require('../..').Name;
var Interest = require('../..').Interest;

// Silence the warning from Interest wire encode.
Interest.setDefaultCanBePrefix(true);

var face = new Face({host: "memoria.ndn.ucla.edu"});
var callbackCount = 0;

var onData = function(interest, data) {
  console.log("Got data packet with name " + data.getName().toUri());
  console.log(data.getContent().buf().toString('binary'));

  if (++callbackCount >= 3)
    // This will cause the script to quit.
    face.close();
};

var onTimeout = function(interest) {
  console.log("Time out for interest " + interest.getName().toUri());

  if (++callbackCount >= 3)
    // This will cause the script to quit.
    face.close();
};

// Try to fetch anything.
var name1 = new Name("/");
console.log("Express name " + name1.toUri());
face.expressInterest(name1, onData, onTimeout);

// Try to fetch using a known name.
var name2 = new Name("/ndn/edu/ucla/remap/demo/ndn-js-test/hello.txt/%FDU%8D%9DM");
console.log("Express name " + name2.toUri());
face.expressInterest(name2, onData, onTimeout);

// Expect this to time out.
var name3 = new Name("/test/timeout");
console.log("Express name " + name3.toUri());
face.expressInterest(name3, onData, onTimeout);
