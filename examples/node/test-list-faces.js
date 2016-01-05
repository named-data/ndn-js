/*
 * Copyright (C) 2015-2016 Regents of the University of California.
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
 * This sends a faces list request to the local NFD and prints the response.
 * This is equivalent to the NFD command line command "nfd-status -f".
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
  // Connect to the local forwarder with a Unix socket.
  var face = new Face(new UnixTransport());

  var interest = new Interest(new Name("/localhost/nfd/faces/list"));
  interest.setInterestLifetimeMilliseconds(4000);
  console.log("Express interest " + interest.getName().toUri());

  SegmentFetcher.fetch
    (face, interest, SegmentFetcher.DontVerifySegment,
     function(content) {
       face.close();  // This will cause the script to quit.
       printFaceStatuses(content);
     },
     function(errorCode, message) {
       face.close();  // This will cause the script to quit.
       console.log(message);
     });
}

/**
 * This is called when all the segments are received to decode the
 * encodedMessage repeated TLV FaceStatus messages and display the values.
 * @param {Blob} encodedMessage The repeated TLV-encoded FaceStatus.
 */
function printFaceStatuses(encodedMessage)
{
  var builder = ProtoBuf.loadProtoFile("../browser/face-status.proto");
  var descriptor = builder.lookup("ndn_message.FaceStatusMessage");
  var FaceStatusMessage = descriptor.build();

  var faceStatusMessage = new FaceStatusMessage();
  ProtobufTlv.decode(faceStatusMessage, descriptor, encodedMessage);

  console.log("Faces:");
  for (var iEntry = 0; iEntry < faceStatusMessage.face_status.length; ++iEntry) {
    var faceStatus = faceStatusMessage.face_status[iEntry];

    // Format to look the same as "nfd-status -f".
    var line = "  faceid=" + faceStatus.face_id +
      " remote=" + faceStatus.uri +
      " local=" + faceStatus.local_uri;
    if (faceStatus.expiration_period != undefined)
      // Convert milliseconds to seconds.
      line += " expires=" +
        Math.round(faceStatus.expiration_period / 1000) + "s";
    line += " counters={" + "in={" + faceStatus.n_in_interests +
      "i " + faceStatus.n_in_datas + "d " + faceStatus.n_in_bytes + "B}" +
      " out={" + faceStatus.n_out_interests + "i "+ faceStatus.n_out_datas +
      "d " + faceStatus.n_out_bytes + "B}" + "}" +
      " " + (faceStatus.face_scope == 1 ? "local" : "non-local") +
      " " + (faceStatus.face_persistency == 2 ? "permanent" :
             faceStatus.face_persistency == 1 ? "on-demand" : "persistent") +
      " " + (faceStatus.link_type == 1 ? "multi-access" : "point-to-point");

    console.log(line);
  }
}

main();
