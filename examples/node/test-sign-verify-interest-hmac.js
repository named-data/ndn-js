/*
 * Copyright (C) 2014-2019 Regents of the University of California.
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

/*
 * This decodes and verifies a hard-coded interest packet with an HMAC signature.
 * Then this creates a fresh interest packet with an HMAC signature, signs and
 * verifies it. For testing, this uses a hard-coded shared secret.
 */

var Interest = require('../..').Interest;
var Name = require('../..').Name;
var Blob = require('../..').Blob;
var KeyChain = require('../..').KeyChain;

var TlvInterest = new Buffer([
0x05, 0x47,   // NDN Interest
  0x07, 0x3f,  // Name
    0x08, 0x03, 0x6e, 0x64, 0x6e, // "ndn"
    0x08, 0x03, 0x61, 0x62, 0x63, // "abc"
    0x08, 0x0f,   // NameComponent
      0x16, 0x0d, // SignatureInfo
        0x1b, 0x01, 0x04, // SignatureType = SignatureHmacWithSha256
        0x1c, 0x08,   // KeyLocator
          0x07, 0x06, // Name
            0x08, 0x04, 0x6b, 0x65, 0x79, 0x31, // "key1"
    0x08, 0x22,   // NameComponent
      0x17, 0x20, // SignatureValue
        0x61, 0xe0, 0x60, 0x58, 0x1e, 0x2b, 0x75, 0x43, 0xf8, 0x8f,
        0xad, 0xa9, 0xdf, 0xa7, 0x6e, 0x43, 0x98, 0x5c, 0xc7, 0x3c,
        0x9b, 0x50, 0xf9, 0x8e, 0xc2, 0x3f, 0xd1, 0x70, 0x79, 0x4d,
        0xf1, 0xe8,
  0x0a, 0x04, 0xd1, 0x3c, 0x4b, 0x2f // Nonce
]);

function main()
{
  // Silence the warning from Interest wire encode.
  Interest.setDefaultCanBePrefix(true);

  var interest = new Interest();
  interest.wireDecode(new Blob(TlvInterest, false));

  // Use a hard-wired secret for testing. In a real application the signer
  // ensures that the verifier knows the shared key and its keyName.
  var key = new Blob(new Buffer([
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
  ]), false);

  if (KeyChain.verifyInterestWithHmacWithSha256(interest, key))
    console.log("Hard-coded interest signature verification: VERIFIED");
  else
    console.log("Hard-coded interest signature verification: FAILED");

  var freshInterest = new Interest(new Name("/ndn/abc"));
  freshInterest.setMustBeFresh(false);
  var keyName = new Name("key1");
  console.log("Signing fresh interest packet " + freshInterest.getName().toUri());
  KeyChain.signWithHmacWithSha256(freshInterest, key, keyName);

  if (KeyChain.verifyInterestWithHmacWithSha256(freshInterest, key))
    console.log("Freshly-signed interest signature verification: VERIFIED");
  else
    console.log("Freshly-signed interest signature verification: FAILED");
}

main();
