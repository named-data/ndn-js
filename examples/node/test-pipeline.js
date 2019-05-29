/*
 * Copyright (C) 2018-2019 Regents of the University of California.
 * @author: Chavoosh Ghasemi <chghasemi@cs.arizona.edu> 
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
var SegmentFetcher = require('../..').SegmentFetcher;
var Log = require('../../js/log.js').Log;

// Silence the warning from Interest wire encode.
Interest.setDefaultCanBePrefix(true);

//var face = new Face({host: "memoria.ndn.ucla.edu"});
var callbackCount = 1;

var onComplete = function(content) {
  console.log("Successfully received the content");
};

// Try to fetch a remote file using Fixed pipeline
var name1 = new Name("/ndn/edu/ucla/remap/demo/ndn-js-test/hello.txt/%FDU%8D%9DM");
console.log("Express name " + name1.toUri());
SegmentFetcher.fetch
  (new Face({host: "memoria.ndn.ucla.edu"}), new Interest(name1),
   null /*validator key*/,
   onComplete, function(errorCode, message) {
     console.log("Error " + errorCode + ": " + message);
   },
   {pipeline: "fixed"} /*pipeline type (default: Cubic) and its options*/
  );


// Try to fetch a local file using Cubic pipeline
// NOTE: A file under "/test/junkfile" needs to be published on the local machine, first
var name2 = new Name("/test/junkfile");
console.log("Express name " + name2.toUri());
SegmentFetcher.fetch
  (new Face({host: "localhost"}), new Interest(name2),
   null /*validator key*/,
   onComplete, function(errorCode, message) {
     console.log("Error " + errorCode + ": " + message);
   },
   null /*pipeline type (default: Cubic) and its options*/
  );

// Expect this to time out
var name3 = new Name("/test/timeout");
console.log("Express name " + name3.toUri());
SegmentFetcher.fetch
  (new Face({host: "localhost"}), new Interest(name3),
   null /*validator key*/,
   onComplete, function(errorCode, message) {
     console.log("Error " + errorCode + ": " + message);
   },
   null /*pipeline type (default: Cubic) and its options*/
  );
