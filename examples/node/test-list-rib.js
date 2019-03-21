/*
 * Copyright (C) 2015-2019 Regents of the University of California.
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

/*
 * This sends a rib list request to the local NFD and prints the response.
 * This is equivalent to the NFD command line command "nfd-status -r".
 * See http://redmine.named-data.net/projects/nfd/wiki/Management .
 */

var ProtoBuf = require("protobufjs");
var Face = require('../..').Face;
var Name = require('../..').Name;
var Interest = require('../..').Interest;
var Blob = require('../..').Blob;
var UnixTransport = require('../..').UnixTransport;
var ProtobufTlv = require('../..').ProtobufTlv;
var SegmentFetcher = require('../..').SegmentFetcher;

function main()
{
  // Silence the warning from Interest wire encode.
  Interest.setDefaultCanBePrefix(true);

  // Connect to the local forwarder with a Unix socket.
  var face = new Face(new UnixTransport());

  var interest = new Interest(new Name("/localhost/nfd/rib/list"));
  interest.setInterestLifetimeMilliseconds(4000);
  console.log("Express interest " + interest.getName().toUri());

  SegmentFetcher.fetch
    (face, interest, null,
     function(content) {
       printRibEntries(content);
       face.close();  // This will cause the script to quit.
     },
     function(errorCode, message) {
       console.log(message);
       face.close();  // This will cause the script to quit.
     });
}

/**
 * This is called when all the segments are received to decode the
 * encodedMessage as repeated TLV RibEntry messages and display the values.
 * @param {Blob} encodedMessage The repeated TLV-encoded RibEntry.
 */
function printRibEntries(encodedMessage)
{
  var builder = ProtoBuf.loadProtoFile("../browser/rib-entry.proto");
  var descriptor = builder.lookup("ndn_message.RibEntryMessage");
  var RibEntryMessage = descriptor.build();

  var ribEntryMessage = new RibEntryMessage();
  ProtobufTlv.decode(ribEntryMessage, descriptor, encodedMessage);

  console.log("RIB:");
  for (var iRibEntry = 0; iRibEntry < ribEntryMessage.rib_entry.length; ++iRibEntry) {
    var ribEntry = ribEntryMessage.rib_entry[iRibEntry];

    var line = "";
    line += ProtobufTlv.toName(ribEntry.name.component).toUri();

    // Show the routes.
    for (var i = 0; i < ribEntry.routes.length; ++i) {
      var route = ribEntry.routes[i];

      line += " route={faceId=" + route.face_id + " (origin=" + route.origin +
        " cost=" + route.cost;
      if ((route.flags & 1) != 0)
        line += " ChildInherit";
      if ((route.flags & 2) != 0)
        line += " Capture";
      if (route.expiration_period != undefined)
        line += " expirationPeriod=" + route.expiration_period;
      line += ")}";
    }

    console.log(line);
  }
}

main();
