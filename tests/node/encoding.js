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

var Name = require('../..').Name;
var Interest = require('../..').Interest;
var Data = require('../..').Data;
var SignedInfo = require('../..').SignedInfo;
var Key = require('../..').Key;
var EncodingUtils = require('../..').EncodingUtils;
var globalKeyManager = require('../..').globalKeyManager;

var n = new Name('/a/b/c.txt');

console.log("Encoding/Decoding interests...");

var i1 = new Interest(n);
i1.interestLifetime = 1000;
i1.childSelector = 1;

var packet = i1.wireEncode();

var i2 = new Interest();
i2.wireDecode(packet);

console.log(i2.getName().toUri());
console.log(i2.interestLifetime);
console.log(i2.childSelector);

console.log("Encoding/Decoding data packet objects...");

var content = "NDN on Node";

var data1 = new Data(new Name(n), new SignedInfo(), content);
data1.getMetaInfo().setFields();
data1.sign();
console.log("Signature is \n" + data1.getSignature().getSignature().toHex());

var p2 = data1.wireEncode();

var data2 = new Data();
data2.wireDecode(p2);

console.log('Decoded name: ' + data2.getName().toUri());
console.log('Decoded content: ' + data2.getContent().buf().toString());

console.log('Data in field values:');
console.log(EncodingUtils.dataToHtml(data2).replace(/<br \/>/g, "\n"));

// Verify with the same key from globalKeyManager used to sign.
if (data2.verify(globalKeyManager.key))
  console.log("SIGNATURE VALID");
else
  console.log("SIGNATURE INVALID");
