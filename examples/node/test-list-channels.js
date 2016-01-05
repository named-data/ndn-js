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
 * This sends a faces channels request to the local NFD and prints the response.
 * This is equivalent to the NFD command line command "nfd-status -c".
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

  var interest = new Interest(new Name("/localhost/nfd/faces/channels"));
  interest.setInterestLifetimeMilliseconds(4000);
  console.log("Express interest " + interest.getName().toUri());

  SegmentFetcher.fetch
    (face, interest, SegmentFetcher.DontVerifySegment,
     function(content) {
       face.close();  // This will cause the script to quit.
       printChannelStatuses(content);
     },
     function(errorCode, message) {
       face.close();  // This will cause the script to quit.
       console.log(message);
     });
}

/**
 * This is called when all the segments are received to decode the
 * encodedMessage repeated TLV ChannelStatus messages and display the values.
 * @param {Blob} encodedMessage The repeated TLV-encoded ChannelStatus.
 */
function printChannelStatuses(encodedMessage)
{
  var builder = ProtoBuf.loadProtoFile("../browser/channel-status.proto");
  var descriptor = builder.lookup("ndn_message.ChannelStatusMessage");
  var ChannelStatusMessage = descriptor.build();

  var channelStatusMessage = new ChannelStatusMessage();
  ProtobufTlv.decode(channelStatusMessage, descriptor, encodedMessage);

  console.log("Channels:");
  for (var iEntry = 0; iEntry < channelStatusMessage.channel_status.length; ++iEntry) {
    var channelStatus = channelStatusMessage.channel_status[iEntry];

    // Format to look the same as "nfd-status -c".
    console.log("  " + channelStatus.local_uri);
  }
}

main();
