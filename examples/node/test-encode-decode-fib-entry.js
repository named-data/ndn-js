/**
 * Copyright (C) 2014-2016 Regents of the University of California.
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

var ProtoBuf = require("protobufjs");
var ProtobufTlv = require('../..').ProtobufTlv;

var builder = ProtoBuf.loadProtoFile("../browser/fib-entry.proto");
var descriptor = builder.lookup("ndn_message.FibEntryMessage");
var FibEntryMessage = descriptor.build();
var message = new FibEntryMessage();
message.fib_entry = new FibEntryMessage.FibEntry();
message.fib_entry.name = new FibEntryMessage.Name();
message.fib_entry.name.add("component", new Buffer("ndn"));
message.fib_entry.name.add("component", new Buffer("ucla"));
var nextHopRecord = new FibEntryMessage.NextHopRecord();
message.fib_entry.add("next_hop_records", nextHopRecord);
nextHopRecord.face_id = 16;
nextHopRecord.cost = 1;

// Encode the Protobuf message object as TLV.
var encoding = ProtobufTlv.encode(message, descriptor);

var decodedMessage = new FibEntryMessage();
ProtobufTlv.decode(decodedMessage, descriptor, encoding);

console.log("Re-decoded FibEntry:");
// This should print the same values that we put in message above.
var value = "";
for (var i = 0; i < decodedMessage.fib_entry.name.component.length; ++i)
  value += "/" + decodedMessage.fib_entry.name.component[i].toString("utf8");
value += " nexthops = {";
for (var i = 0; i < decodedMessage.fib_entry.next_hop_records.length; ++i)
  value += "faceid=" + decodedMessage.fib_entry.next_hop_records[i].face_id
           + " (cost=" + decodedMessage.fib_entry.next_hop_records[i].cost + ")";
value += " }";
console.log(value);
