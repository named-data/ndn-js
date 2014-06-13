/*
 * Copyright (C) 2014 Regents of the University of California.
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

var Face = require('../..').Face;
var Name = require('../..').Name;
var Interest = require('../..').Interest;
var Data = require('../..').Data;
var SignedInfo = require('../..').SignedInfo;
var Closure = require('../..').Closure;

function onInterest(prefix, interest, transport) 
{
  console.log("Interest received : " + interest.name.toUri());

  // Make and sign a Data packet.
  var contentString = "Echo " + interest.name.toUri();
  var data = new Data(interest.name, new SignedInfo(), new Buffer(contentString));
  data.signedInfo.setFields();
  data.sign();
  var encodedData = data.wireEncode();

  try {
    console.log("Send content " + contentString);
    transport.send(encodedData.buf());
  } catch (e) {
    console.log(e.toString());
  }
}

function onRegisterFailed(prefix) 
{
  console.log("Register failed for prefix " + prefix.toUri());
  face.close();  // This will cause the script to quit.
}

var face = new Face({host: "localhost"});

face.registerPrefix(new Name("/testecho"), onInterest, onRegisterFailed);
console.log("Started...");
