/**
 * Copyright (C) 2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/command-interest-signer.cpp
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

// Use capitalized Crypto to not clash with the browser's crypto.subtle.
/** @ignore */
var Crypto = require('../crypto.js'); /** @ignore */
var Interest = require('../interest.js').Interest; /** @ignore */
var WireFormat = require('../encoding/wire-format.js').WireFormat; /** @ignore */
var TlvEncoder = require('../encoding/tlv/tlv-encoder.js').TlvEncoder; /** @ignore */
var Blob = require('../util/blob.js').Blob; /** @ignore */

/**
 * A CommandInterestPreparer keeps track of a timestamp and prepares a command
 * interest by adding a timestamp and nonce to the name of an Interest. This
 * class is primarily designed to be used by the CommandInterestSigner, but can
 * also be using in an application that defines custom signing methods not
 * supported by the KeyChain (such as HMAC-SHA1). See the Command Interest
 * documentation:
 * https://redmine.named-data.net/projects/ndn-cxx/wiki/CommandInterest
 *
 * Create a CommandInterestPreparer and initialize the timestamp to now.
 * @constructor
 */
var CommandInterestPreparer = function CommandInterestPreparer()
{
  this.lastUsedTimestamp_ = Math.round(new Date().getTime());
  this.nowOffsetMilliseconds_ = 0;
};

exports.CommandInterestPreparer = CommandInterestPreparer;

/**
 * Append a timestamp component and a random nonce component to interest's
 * name. This ensures that the timestamp is greater than the timestamp used in
 * the previous call.
 * @param {Interest} interest The interest whose name is append with components.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the SignatureInfo. If omitted, use WireFormat getDefaultWireFormat().
 */
CommandInterestPreparer.prototype.prepareCommandInterestName = function
  (interest, wireFormat)
{
  if (wireFormat == undefined)
    wireFormat = WireFormat.getDefaultWireFormat();

  // nowOffsetMilliseconds_ is only used for testing.
  var now = new Date().getTime() + this.nowOffsetMilliseconds_;
  var timestamp = Math.round(now);
  while (timestamp <= this.lastUsedTimestamp_)
    timestamp += 1.0;

  // Update the timestamp now. In the small chance that signing fails, it just
  // means that we have bumped the timestamp.
  this.lastUsedTimestamp_ = timestamp;

  // The timestamp is encoded as a TLV nonNegativeInteger.
  var encoder = new TlvEncoder(8);
  encoder.writeNonNegativeInteger(timestamp);
  interest.getName().append(new Blob(encoder.getOutput(), false));

  // The random value is a TLV nonNegativeInteger too, but we know it is 8
  // bytes, so we don't need to call the nonNegativeInteger encoder.
  interest.getName().append(new Blob(Crypto.randomBytes(8), false));
};

/**
 * Set the offset for when prepareCommandInterestName() gets the current time,
 * which should only be used for testing.
 * @param {number} nowOffsetMilliseconds The offset in milliseconds.
 */
CommandInterestPreparer.prototype.setNowOffsetMilliseconds_ = function
  (nowOffsetMilliseconds)
{
  this.nowOffsetMilliseconds_ = nowOffsetMilliseconds;
};
